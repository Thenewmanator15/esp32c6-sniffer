"""Live 802.15.4 capture session.

Opens the board, selects a channel and antenna, and yields IEEE 802.15.4 TAP
records ready for a pcap stream. Used by both the command-line tool and the
Wireshark extcap plugin, so the two cannot drift apart.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from typing import Iterator

import serial

from .control import Antenna, Command, decode_reply, encode_command
from .framing import FrameType
from .parser import SequenceTracker, StreamParser
from .tap import CHANNEL_MAX, CHANNEL_MIN, FcsType, build_tap_record

# Matches sn_154_meta_t in firmware/main/radio154.h
_META = struct.Struct("<BBbBQ")  # channel, lqi, rssi_dbm, flags, timestamp_us
META_LEN = _META.size

FLAG_HAS_FCS = 0x01


# Matches the packed struct the capture build emits once a second:
# sn_link_stats_t (5 x uint32) then sn_154_stats_t (3 x uint32).
_STATS = struct.Struct("<8I")


@dataclass
class CaptureStats:
    frames: int = 0
    bytes_captured: int = 0
    sequence_gaps: int = 0
    resyncs: int = 0
    bytes_discarded: int = 0
    # Reported by the board. Any non-zero drop here is a defect on this radio,
    # not a bandwidth limit: a saturated channel is about a twenty-fifth of
    # what the link carries.
    fw_frames_captured: int = 0
    fw_isr_queue_full: int = 0
    fw_link_rejected: int = 0
    fw_frames_dropped_ringfull: int = 0
    fw_tx_stalls: int = 0

    @property
    def lossless(self) -> bool:
        return (
            self.sequence_gaps == 0
            and self.fw_isr_queue_full == 0
            and self.fw_link_rejected == 0
            and self.fw_frames_dropped_ringfull == 0
        )


class CaptureSession:
    """One capture run against the board.

    Timestamps need anchoring. The board reports microseconds from its own
    boot, so the first frame's device time is pinned to the host clock and
    every later frame is offset from that. This keeps inter-frame spacing at
    the board's resolution while putting the capture at a sensible wall-clock
    time. It does not correct for clock drift between the two.
    """

    def __init__(
        self,
        port: str,
        channel: int,
        antenna: Antenna = Antenna.INTERNAL,
        timeout: float = 0.05,
    ) -> None:
        self._port_name = port
        self._channel = channel
        self._antenna = antenna
        self._timeout = timeout
        self._serial: serial.Serial | None = None
        self._parser = StreamParser()
        self._tracker = SequenceTracker()
        self._t0_device: int | None = None
        self._t0_host: float = 0.0
        self._pending_channel: int | None = None
        self._pending_lock = threading.Lock()
        # Frames that arrive while waiting for a command reply. Without this
        # they were parsed and dropped, so every channel change silently lost
        # whatever was in flight, showing up as sequence gaps the board could
        # not account for.
        self._deferred: list = []
        self.stats = CaptureStats()

    def __enter__(self) -> "CaptureSession":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def open(self) -> None:
        ser = serial.Serial(self._port_name, 115200, timeout=self._timeout)
        try:
            # pyserial opens Windows ports with only a 4 KB receive buffer, and
            # the board discards data when the host stops draining.
            ser.set_buffer_size(rx_size=1 << 20)
        except (AttributeError, OSError):
            pass
        ser.reset_input_buffer()
        self._serial = ser

        self._command(Command.SET_ANTENNA, int(self._antenna))
        self._command(Command.SET_CHANNEL, self._channel)

    def close(self) -> None:
        if self._serial is None:
            return
        try:
            self._serial.write(encode_command(Command.STOP))
            self._serial.flush()
        except (serial.SerialException, OSError):
            pass
        self._serial.close()
        self._serial = None

    def _command(self, command: Command, value: int = 0, timeout: float = 5.0) -> dict:
        assert self._serial is not None
        self._serial.write(encode_command(command, value))
        self._serial.flush()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for frame in self._parser.feed(self._serial.read(4096)):
                # Every frame is deferred, replies included, so records()
                # observes them all in arrival order. Two rules matter here and
                # both were learned the hard way. Replies consume a sequence
                # number on the board, so skipping them entirely invents gaps.
                # And observing a reply here while earlier frames wait in the
                # deferred list feeds the tracker out of order, which the
                # modulo-65536 arithmetic turns into gaps of tens of thousands.
                self._deferred.append(frame)
                if frame.ftype is not FrameType.CONTROL_REPLY:
                    continue
                reply = decode_reply(frame.payload)
                if reply["command"] is command:
                    if not reply["ok"]:
                        raise RuntimeError(
                            f"{command.name} failed, status {reply['status']}"
                        )
                    return reply
        raise TimeoutError(f"no reply to {command.name} within {timeout}s")

    def request_channel(self, channel: int) -> None:
        """Ask for a channel change from another thread.

        Deliberately does not touch the serial port. The capture loop owns it,
        and two threads writing commands into the same stream would interleave
        bytes mid-frame. This only sets a flag; records() applies it between
        reads.

        A retune costs frames. Measured over 5 minutes with a change every
        20 seconds: 7 sequence gaps across 14 retunes, against 0 gaps in 1920
        frames with no retuning. That is roughly half a frame per change,
        lost in flight while the radio is briefly off-channel. It is inherent
        rather than a defect, but it means `stats.lossless` will read False
        after any retune, and that is honest rather than broken.
        """
        if not CHANNEL_MIN <= channel <= CHANNEL_MAX:
            raise ValueError(f"channel {channel} outside {CHANNEL_MIN}-{CHANNEL_MAX}")
        with self._pending_lock:
            self._pending_channel = channel

    def _apply_pending_channel(self) -> int | None:
        with self._pending_lock:
            channel = self._pending_channel
            self._pending_channel = None
        if channel is None:
            return None
        self._command(Command.SET_CHANNEL, channel)
        self._channel = channel
        # Timestamps are anchored to the first frame; retuning does not restart
        # the board's clock, so the anchor stays valid.
        return channel

    def _anchor(self, device_us: int) -> float:
        if self._t0_device is None:
            self._t0_device = device_us
            self._t0_host = time.time()
        return self._t0_host + (device_us - self._t0_device) / 1_000_000.0

    def records(self) -> Iterator[tuple[bytes, float]]:
        """Yields (tap_record, wall_clock_timestamp) until the session closes."""
        assert self._serial is not None, "call open() first"
        while self._serial is not None:
            self._apply_pending_channel()
            chunk = self._serial.read(8192)
            frames = self._deferred + self._parser.feed(chunk)
            self._deferred = []
            if not frames:
                continue
            for frame in frames:
                gap = self._tracker.observe(frame.seq)
                self.stats.sequence_gaps += gap

                if frame.ftype is FrameType.STATS:
                    if len(frame.payload) >= _STATS.size:
                        (
                            _sent,
                            self.stats.fw_frames_dropped_ringfull,
                            _short,
                            self.stats.fw_tx_stalls,
                            _bytes,
                            self.stats.fw_frames_captured,
                            self.stats.fw_isr_queue_full,
                            self.stats.fw_link_rejected,
                        ) = _STATS.unpack_from(frame.payload)
                    continue

                if frame.ftype is not FrameType.PACKET:
                    continue
                if len(frame.payload) <= META_LEN:
                    continue

                channel, lqi, rssi, flags, device_us = _META.unpack_from(
                    frame.payload
                )
                psdu = frame.payload[META_LEN:]
                fcs = (
                    FcsType.CRC16 if flags & FLAG_HAS_FCS else FcsType.NONE
                )
                record = build_tap_record(
                    psdu,
                    channel=channel,
                    rssi_dbm=float(rssi),
                    lqi=lqi,
                    fcs_type=fcs,
                )
                self.stats.frames += 1
                self.stats.bytes_captured += len(psdu)
                self.stats.resyncs = self._parser.resync_count
                self.stats.bytes_discarded = self._parser.bytes_discarded
                yield record, self._anchor(device_us)
