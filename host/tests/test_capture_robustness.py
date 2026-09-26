"""A capture should survive what the link and the board actually do: packets
arriving in the same read as a reply, a reply that never comes, a port that
vanishes, a frame cut short at the end of a burst. Each of these used to lose
data silently or end the capture."""

import struct
import time

import pytest
import serial

from esp32c6_sniffer import capture
from esp32c6_sniffer.ble import hci_of_record
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Command, Radio
from esp32c6_sniffer.framing import FrameType, encode_frame

from esp32c6_sniffer.ble_keys import make_rpa

from test_ble_keys_capture import IRK, KeyedBoard, ext_report, open_session


def reports(n: int) -> list[bytes]:
    return [ext_report(make_rpa(IRK, 0x400001 + i)) for i in range(n)]


def test_packets_heard_right_after_start_are_kept(monkeypatch):
    """They arrive in the same read as START's reply, which deferred them,
    and the session then cleared the deferred list to start counting afresh.
    Measured with a fake board: 5 packets sent straight after the reply,
    3 later, and only the 3 reached records()."""
    board = KeyedBoard("nrf54l15")
    first = reports(5)
    board.after[Command.START] = [first]
    session = open_session(monkeypatch, board)
    records = session.records()
    got = [hci_of_record(next(records)[0]) for _ in range(5)]
    assert got == first
    assert session.stats.sequence_gaps == 0


def test_a_failed_open_closes_the_port(monkeypatch):
    """__exit__ does not run when __enter__ raises, so a version mismatch or
    an unanswered command left the port open and the radio configured."""
    board = KeyedBoard("nrf54l15")
    board.version = 1
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: board)
    session = CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE,
                             board="nrf54l15", baud=1_000_000)
    with pytest.raises(RuntimeError, match="firmware version"):
        session.open()
    assert board.closed


def test_a_lost_reply_mid_capture_does_not_end_the_capture(monkeypatch):
    """A retune, hop, antenna switch or Check keys sends a command from
    inside the capture loop. Either board drops a reply when its ring is
    full, and the TimeoutError that followed ended the whole capture."""
    monkeypatch.setattr(capture, "MID_CAPTURE_REPLY_S", 0.2)
    board = KeyedBoard("nrf54l15")
    session = open_session(monkeypatch, board)
    board.unanswered.add(Command.SET_ANTENNA)
    board.after[Command.SET_ANTENNA] = [reports(2)]
    records = session.records()
    session.request_antenna(1)
    got = [hci_of_record(next(records)[0]) for _ in range(2)]
    assert got == reports(2)
    assert session.stats.commands_unanswered == 1


def test_a_vanished_port_is_reported_at_once(monkeypatch):
    """The wait for a reply swallowed the port's own error, so an unplugged
    board was reported five seconds later as one that did not answer."""
    board = KeyedBoard("nrf54l15")
    session = open_session(monkeypatch, board)

    def gone():
        raise serial.SerialException("ClearCommError failed: device removed")

    monkeypatch.setattr(type(board), "in_waiting", property(lambda self: gone()))
    with pytest.raises(serial.SerialException):
        session._command(Command.GET_INFO, timeout=5.0)


def test_a_frame_cut_short_does_not_hold_back_the_reply_behind_it(monkeypatch):
    """The nRF's bridge can drop the tail of a burst. The header survives and
    declares bytes that never come, and the parser waits for them -- with the
    reply behind it inside the wait. On a quiet link nothing arrives to fill
    the hole, and the command timed out although the board had answered."""
    monkeypatch.setattr(capture, "STALL_RESYNC_S", 0.2)
    board = KeyedBoard("nrf54l15")
    session = open_session(monkeypatch, board)
    cut = encode_frame(FrameType.BLE_BATCH, board.seq, b"\x00" * 1200)[:319]
    board.seq += 1
    board.before[Command.SET_ANTENNA] = [[]]
    real_emit = board._emit

    def emit(queues, command):
        if queues is board.before and command == Command.SET_ANTENNA:
            board.rx += cut
        real_emit(queues, command)

    monkeypatch.setattr(board, "_emit", emit)
    reply = session._command(Command.SET_ANTENNA, 0, timeout=3.0)
    assert reply["ok"]


def test_ble_has_no_channel_to_request(monkeypatch):
    """It was accepted, and the capture thread then died applying it."""
    session = open_session(monkeypatch, KeyedBoard("nrf54l15"))
    with pytest.raises(ValueError, match="no selectable channel"):
        session.request_channel(15)


_154_META = struct.Struct("<BBbBQ")


def _154_packet(board, psdu: bytes, timestamp: int) -> None:
    board.rx += encode_frame(FrameType.PACKET, board.seq,
                             _154_META.pack(11, 200, -40, 0, timestamp) + psdu)
    board.seq += 1


def test_a_quiet_link_does_not_let_a_transmitter_forge_a_frame(monkeypatch):
    """A radio frame carrying a sniffer header, on a channel where nothing
    follows it for a while. Measured through a session: the real packet was
    lost, the transmitter's packet -- channel 26, a timestamp an hour on --
    was delivered, and the next frame counted 65536 sequence gaps."""
    monkeypatch.setattr(capture, "STALL_RESYNC_S", 0.2)

    class QuietBoard(KeyedBoard):
        def read(self, n=1):
            if not self.rx:
                time.sleep(0.01)
            return super().read(n)

    board = QuietBoard("esp32c6")
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: board)
    session = CaptureSession("COM_UNUSED", channel=11, radio=Radio.IEEE802154)
    session.open()
    forged = encode_frame(FrameType.PACKET, (board.seq + 3) & 0xFFFF,
                          _154_META.pack(26, 255, 0, 0, 3_600_000_000)
                          + b"FORGED")
    psdu = b"\x41\x88" + forged + b"\x00" * 4
    _154_packet(board, psdu, 1_000_000)
    records = session.records()
    first = next(records)
    _154_packet(board, b"\x41\x88" + b"B" * 20, 1_100_000)
    second = next(records)
    assert first[0].endswith(psdu) and second[0].endswith(b"B" * 20)
    assert session.stats.sequence_gaps == 0


def test_a_malformed_reply_does_not_end_the_command(monkeypatch):
    """A CONTROL_REPLY too short to decode raised ControlError out of the
    wait for the real one, and nothing above it caught that."""
    board = KeyedBoard("esp32c6")
    session = open_session(monkeypatch, board, name="esp32c6")
    real_emit = board._emit

    def emit(queues, command):
        if queues is board.before and command == Command.SET_ANTENNA:
            board.rx += encode_frame(FrameType.CONTROL_REPLY, board.seq, b"")
            board.seq += 1
        real_emit(queues, command)

    monkeypatch.setattr(board, "_emit", emit)
    assert session._command(Command.SET_ANTENNA, 0, timeout=2.0)["ok"]
