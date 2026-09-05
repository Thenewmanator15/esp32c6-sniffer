"""Live 802.15.4 capture session.

Opens the board, selects a channel and antenna, and yields IEEE 802.15.4 TAP
records ready for a pcap stream. Used by both the command-line tool and the
Wireshark extcap plugin, so the two cannot drift apart.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Iterator

import serial

from .control import Antenna, Command, decode_reply, encode_command
from .framing import FrameType
from .parser import SequenceTracker, StreamParser
from .tap import FcsType, build_tap_record

# Matches sn_154_meta_t in firmware/main/radio154.h
_META = struct.Struct("<BBbBQ")  # channel, lqi, rssi_dbm, flags, timestamp_us
META_LEN = _META.size

FLAG_HAS_FCS = 0x01


@dataclass
class CaptureStats:
    frames: int = 0
    bytes_captured: int = 0
    sequence_gaps: int = 0
    resyncs: int = 0
    bytes_discarded: int = 0


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
                if frame.ftype is FrameType.CONTROL_REPLY:
                    reply = decode_reply(frame.payload)
                    if reply["command"] is command:
                        if not reply["ok"]:
                            raise RuntimeError(
                                f"{command.name} failed, status {reply['status']}"
                            )
                        return reply
        raise TimeoutError(f"no reply to {command.name} within {timeout}s")

    def _anchor(self, device_us: int) -> float:
        if self._t0_device is None:
            self._t0_device = device_us
            self._t0_host = time.time()
        return self._t0_host + (device_us - self._t0_device) / 1_000_000.0

    def records(self) -> Iterator[tuple[bytes, float]]:
        """Yields (tap_record, wall_clock_timestamp) until the session closes."""
        assert self._serial is not None, "call open() first"
        while self._serial is not None:
            chunk = self._serial.read(8192)
            if not chunk:
                continue
            for frame in self._parser.feed(chunk):
                gap = self._tracker.observe(frame.seq)
                self.stats.sequence_gaps += gap
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
