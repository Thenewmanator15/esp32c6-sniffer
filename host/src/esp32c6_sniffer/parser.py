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

#: How far ahead of a damaged frame the next surviving one can plausibly be. A
#: truncation is followed by the frame after it, or a few later if whole frames
#: went with it; 64 allows for that and still rules out nearly all of the 65536
#: numbers a chance match inside a payload could carry.
_TRUNCATION_SEQ_WINDOW = 64


class StreamParser:
    """Accumulates bytes and yields whole frames, resynchronising after loss."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.resync_count = 0
        self.bytes_discarded = 0
        self.frames_parsed = 0
        #: Frames that decoded but had lost their tail in transit, detected by
        #: a header starting inside them. Dropped rather than delivered.
        self.frames_truncated = 0

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

        On a live stream the stall rarely lasts: the next frame's bytes arrive
        and fill the declared length, and the splice this avoids by waiting
        would happen anyway. _inner_header_at catches it at that point.
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
            cut = self._inner_header_at(len(frame.payload), frame.seq)
            if cut is not None:
                # Lost its tail in transit; see _inner_header_at. The damaged
                # frame is dropped and parsing resumes at the header inside
                # it, which is the frame that followed -- recovered rather than
                # lost in the damaged one's place.
                self.bytes_discarded += cut
                self.resync_count += 1
                self.frames_truncated += 1
                del self._buf[:cut]
                continue
            del self._buf[: HEADER_LEN + len(frame.payload)]
            self.frames_parsed += 1
            return frame

    def _inner_header_at(self, length: int, seq: int) -> int | None:
        """Where a frame header begins inside this frame's payload, if one does.

        The header CRC covers only the header, so a frame whose tail was lost in
        transit still decodes: its header declares the full length, and the
        bytes of whatever followed fill it out. The nRF54L15's SAMD11 bridge
        does exactly this -- it holds 319 bytes and drops the rest of a burst
        while its USB side is stalled -- and 6 of 13 such BLE batches measured
        on the board went on to decode as valid.

        The frame that followed shows up as a whole header starting inside the
        declared payload: magic, a header CRC that matches, a length a frame
        could have, and a sequence number just ahead of this one. A payload
        holds all four by chance about once in 2^42 positions.

        Only headers already wholly buffered are examined. Waiting for one still
        arriving would hold frames back -- control replies among them -- for
        bytes a quiet link may not send for a second.
        """
        end = HEADER_LEN + length
        pos = self._buf.find(_MAGIC_BYTES, HEADER_LEN, end + 1)
        while pos != -1:
            if len(self._buf) < pos + HEADER_LEN:
                return None
            head = bytes(self._buf[pos:pos + 8])
            crc = struct.unpack_from("<H", self._buf, pos + 8)[0]
            inner_seq, inner_len = struct.unpack_from("<HH", head, 4)
            if (crc16_ccitt_false(head) == crc and inner_len <= MAX_PAYLOAD
                    and 1 <= (inner_seq - seq) % 65536
                    <= _TRUNCATION_SEQ_WINDOW):
                return pos
            pos = self._buf.find(_MAGIC_BYTES, pos + 1, end + 1)
        return None

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
