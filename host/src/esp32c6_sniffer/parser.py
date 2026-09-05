"""Streaming frame parser that recovers from mid-stream data loss.

The firmware discards bytes when the host stops reading, so an arbitrary run can
vanish from the middle of the stream. The parser must find the next real frame
rather than misparsing, and must report how much it threw away.
"""

from __future__ import annotations

import struct

from .framing import (
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    Frame,
    FrameError,
    crc16_ccitt_false,
    decode_frame,
)

_MAGIC_BYTES = struct.pack("<H", MAGIC)


class StreamParser:
    """Accumulates bytes and yields whole frames, resynchronising after loss."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.resync_count = 0
        self.bytes_discarded = 0
        self.frames_parsed = 0

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        frames: list[Frame] = []
        while True:
            frame = self._try_one()
            if frame is None:
                return frames
            frames.append(frame)

    def force_resync(self) -> list[Frame]:
        """Abandon a partially received frame and hunt for the next one.

        The header CRC covers only the header, so a frame truncated by data loss
        still presents a valid header declaring a length that will never arrive.
        That is indistinguishable from a payload still in flight, so the parser
        waits rather than guessing. Guessing would splice the following frame's
        bytes into this one's payload and emit a corrupt frame. Only the caller
        knows it has timed out, so the caller breaks the stall.
        """
        if self._buf:
            self._discard_one_byte_and_resync()
        return self.feed(b"")

    def _try_one(self) -> Frame | None:
        while True:
            if len(self._buf) < HEADER_LEN:
                return None
            try:
                frame = decode_frame(bytes(self._buf))
            except FrameError:
                # Either this is not a frame start, or the payload has not
                # arrived yet. A valid header with a short payload must wait.
                if self._header_is_valid_but_incomplete():
                    return None
                self._discard_one_byte_and_resync()
                continue
            del self._buf[: HEADER_LEN + len(frame.payload)]
            self.frames_parsed += 1
            return frame

    def _header_is_valid_but_incomplete(self) -> bool:
        head = bytes(self._buf[:8])
        if head[:2] != _MAGIC_BYTES:
            return False
        if crc16_ccitt_false(head) != struct.unpack("<H", self._buf[8:10])[0]:
            return False
        length = struct.unpack("<H", head[6:8])[0]
        if length > MAX_PAYLOAD:
            return False
        return len(self._buf) < HEADER_LEN + length

    def _discard_one_byte_and_resync(self) -> None:
        """Drop the leading byte, then jump to the next plausible magic."""
        del self._buf[0]
        self.bytes_discarded += 1
        idx = self._buf.find(_MAGIC_BYTES)
        if idx > 0:
            self.bytes_discarded += idx
            del self._buf[:idx]
        elif idx == -1:
            # Keep only a possible split magic byte at the tail.
            keep = 1 if self._buf[-1:] == _MAGIC_BYTES[:1] else 0
            drop = len(self._buf) - keep
            if drop > 0:
                self.bytes_discarded += drop
                del self._buf[:drop]
        self.resync_count += 1


class SequenceTracker:
    """Counts frames missing between consecutive sequence numbers."""

    def __init__(self) -> None:
        self._last: int | None = None
        self.total_missed = 0

    def observe(self, seq: int) -> int:
        if self._last is None:
            self._last = seq
            return 0
        missed = (seq - self._last - 1) % 65536
        self._last = seq
        self.total_missed += missed
        return missed
