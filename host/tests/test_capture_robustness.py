"""A capture should survive what the link and the board actually do: packets
arriving in the same read as a reply, a reply that never comes, a port that
vanishes, a frame cut short at the end of a burst. Each of these used to lose
data silently or end the capture."""

import struct

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
