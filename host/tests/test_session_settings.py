"""Every BLE capture says every setting, rather than only the ones switched on.

The nRF54L15 does not reset when its port opens, and it kept whatever the
last capture set. The host sent periodic following only when it was on, and
the scan interval and window only when they were not zero, so after one
capture that followed periodic trains every later capture followed them too
-- about twice the record rate, which the README prices at 0.4% link loss.
"""

import struct

from esp32c6_sniffer.control import Command

from test_ble_keys_capture import KeyedBoard, open_session


def values(board, command):
    return [struct.unpack_from("<BI", payload)[1]
            for _, c, payload in board.written if c == command]


def test_periodic_following_is_turned_off_when_not_asked_for(monkeypatch):
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board)
    assert values(board, Command.SET_BLE_PERIODIC) == [0]


def test_the_scan_timing_is_sent_even_when_left_at_the_default(monkeypatch):
    """Zero is each firmware's default, so saying zero puts it back."""
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board)
    assert values(board, Command.SET_BLE_SCAN) == [0]


def test_both_go_before_start(monkeypatch):
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board)
    names = board.sequence()
    assert names.index("SET_BLE_PERIODIC") < names.index("START")
    assert names.index("SET_BLE_SCAN") < names.index("START")
