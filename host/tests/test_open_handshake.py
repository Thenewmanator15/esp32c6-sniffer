"""Opening a session through the nRF54L15's SAMD11 bridge.

The bridge keeps whole USB packets that were in flight when the previous
session closed, and releases them in front of the next thing the board sends.
On opening, that is the reply to GET_INFO. The stale frame was cut at a packet
boundary, so its header declares more payload than it kept, and the reply fills
the gap: never seen, and open() used to time out after five seconds. Measured on
the board: a 143-byte batch delivered as 128, then a reply 82 sequence numbers
later -- too far for the parser's truncation check to trust, because the board
kept counting through forty seconds of the port being closed.
"""
import struct

import pytest

from esp32c6_sniffer import capture
from esp32c6_sniffer.capture import CaptureSession, EXPECTED_FIRMWARE_VERSIONS
from esp32c6_sniffer.control import Command, Radio
from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import StreamParser

#: The measured case: a BLE batch of 143 bytes, 128 of them delivered.
STALE = encode_frame(FrameType.BLE_BATCH, 11704, b"\x00" * 133)[:128]


class BridgedPort:
    """Answers commands as the firmware does, and hands over whatever the
    bridge was holding in front of the first answer."""

    def __init__(self, version: int, stale: bytes = b""):
        self.version = version
        self.stale = stale
        self.rx = bytearray()
        self.seq = 11786
        self.commands: list[int] = []

    def set_buffer_size(self, **_):
        pass

    def reset_input_buffer(self):
        self.rx.clear()

    @property
    def in_waiting(self):
        return len(self.rx)

    def read(self, n=1):
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def flush(self):
        pass

    def close(self):
        pass

    def write(self, data):
        for frame in StreamParser().feed(bytes(data)):
            if frame.ftype is not FrameType.CONTROL_CMD:
                continue
            command, value = struct.unpack_from("<BI", frame.payload)
            self.commands.append(command)
            if command == Command.GET_INFO:
                value = self.version
            reply = encode_frame(FrameType.CONTROL_REPLY, self.seq,
                                 struct.pack("<BBI", command, 0, value))
            self.seq += 1
            self.rx += self.stale + reply
            self.stale = b""
        return len(data)


def session(monkeypatch, board, port):
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: port)
    return CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE,
                          board=board, baud=1_000_000)


def test_a_reply_eaten_by_stale_bridge_data_is_asked_for_again(monkeypatch):
    port = BridgedPort(EXPECTED_FIRMWARE_VERSIONS["nrf54l15"], stale=STALE)
    s = session(monkeypatch, "nrf54l15", port)

    s.open()

    assert s.firmware_version == EXPECTED_FIRMWARE_VERSIONS["nrf54l15"]
    assert port.commands[:2] == [Command.GET_INFO, Command.GET_INFO]


def test_a_clean_bridge_costs_no_extra_round_trip(monkeypatch):
    port = BridgedPort(EXPECTED_FIRMWARE_VERSIONS["nrf54l15"])
    s = session(monkeypatch, "nrf54l15", port)

    s.open()

    assert port.commands.count(Command.GET_INFO) == 1


def test_the_c6_path_is_unchanged(monkeypatch):
    """The C6 resets when its port opens and has nothing stale to hand over,
    so it asks once, with the ordinary timeout, exactly as before."""
    port = BridgedPort(EXPECTED_FIRMWARE_VERSIONS["esp32c6"])
    s = session(monkeypatch, "esp32c6", port)

    s.open()

    assert port.commands.count(Command.GET_INFO) == 1
