"""A BLE capture carrying device keys, against a board faked at the frame
level. The board is the one that answers; these check what the host sends it
and in which order, and what the host does with what comes back."""

import struct

import pytest

from esp32c6_sniffer import capture
from esp32c6_sniffer.ble import hci_of_record
from esp32c6_sniffer.ble_keys import DeviceKey, make_rpa
from esp32c6_sniffer.capture import CaptureSession, EXPECTED_FIRMWARE_VERSIONS
from esp32c6_sniffer.control import Command, Radio
from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import StreamParser

IRK = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
IDENTITY = "de:ad:be:ef:00:01"
KEY = DeviceKey(1, 1, IDENTITY, IRK)


def ext_report(address: str, address_type: int = 1) -> bytes:
    """One LE Extended Advertising Report, as the controller sends it."""
    raw = bytes.fromhex(address.replace(":", ""))[::-1]
    body = bytearray([1, 0x10, 0x00, address_type]) + raw
    body += bytes([0x01, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00, 0x00]) + bytes(6)
    body += bytes([0])
    return bytes([0x04, 0x3E, len(body) + 1, 0x0D]) + bytes(body)


class KeyedBoard:
    """Answers commands as the firmware does and records every frame written.

    before[cmd] and after[cmd] are queues of packet lists: each time that
    command arrives, the next list is sent ahead of its reply or behind it.
    That is how a test puts a packet on either side of a STOP."""

    def __init__(self, board: str):
        self.version = EXPECTED_FIRMWARE_VERSIONS[board]
        self.rx = bytearray()
        self.seq = 0
        self.written: list[tuple[FrameType, int | None, bytes]] = []
        self.before: dict[int, list[list[bytes]]] = {}
        self.after: dict[int, list[list[bytes]]] = {}
        self.reads = 0

    def set_buffer_size(self, **_):
        pass

    def reset_input_buffer(self):
        self.rx.clear()

    @property
    def in_waiting(self):
        return len(self.rx)

    def flush(self):
        pass

    def close(self):
        pass

    def read(self, n=1):
        self.reads += 1
        if self.reads > 20000:
            raise AssertionError("records() never produced what the test waited for")
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def packet(self, hci: bytes) -> None:
        payload = struct.pack("<QHBB", 1000 * (self.seq + 1), len(hci), 0, 0) + hci
        self.rx += encode_frame(FrameType.PACKET, self.seq, payload)
        self.seq += 1

    def _emit(self, queues, command):
        queue = queues.get(command)
        if queue:
            for hci in queue.pop(0):
                self.packet(hci)

    def write(self, data):
        for frame in StreamParser().feed(bytes(data)):
            if frame.ftype is not FrameType.CONTROL_CMD:
                self.written.append((frame.ftype, None, frame.payload))
                continue
            command, value = struct.unpack_from("<BI", frame.payload)
            self.written.append((frame.ftype, command, frame.payload))
            self._emit(self.before, command)
            if command == Command.GET_INFO:
                value = self.version
            self.rx += encode_frame(FrameType.CONTROL_REPLY, self.seq,
                                    struct.pack("<BBI", command, 0, value))
            self.seq += 1
            self._emit(self.after, command)
        return len(data)

    def sequence(self):
        """What was sent, as short names, commands by name."""
        return [Command(c).name if c is not None else t.name
                for t, c, _ in self.written]


def open_session(monkeypatch, board, keys=None, entries=None, name="nrf54l15"):
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: board)
    session = CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE,
                             board=name, baud=1_000_000,
                             ble_keys=keys, ble_filter=entries)
    session.open()
    return session


def test_keys_then_filter_then_start(monkeypatch):
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board, [KEY], [(1, IDENTITY)])
    names = board.sequence()
    assert names.index("BLE_KEYS") < names.index("BLE_FILTER") < names.index("START")


def test_both_lists_are_sent_even_when_empty(monkeypatch):
    """The nRF54L15 does not reset when its port opens, so a filter left
    from the last capture would otherwise still apply."""
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board)
    sent = {t: p for t, c, p in board.written if c is None}
    assert sent[FrameType.BLE_KEYS] == b""
    assert sent[FrameType.BLE_FILTER] == b""


def test_more_keys_than_the_board_holds_is_refused():
    keys = [DeviceKey(n, 0, f"11:22:33:44:55:{n:02x}", IRK) for n in range(6)]
    with pytest.raises(ValueError, match="holds 5"):
        CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE,
                       board="esp32c6", ble_keys=keys)
