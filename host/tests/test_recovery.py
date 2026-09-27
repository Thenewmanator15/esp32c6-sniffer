"""Handing the front end back after 802.15.4 was left running.

Measured on the ESP32-C6, 2026-09-27: with 802.15.4 left running when the
host went, the Wi-Fi receiver went deaf every time. The power-gate the
recovery used usually cured it, but left two episodes deaf through 16
attempts, one of them for an hour. Starting 802.15.4 and stopping it cleanly
has cured every episode it was tried on -- with no time spent receiving.
"""

from esp32c6_sniffer import recovery
from esp32c6_sniffer.control import Command

from test_ble_keys_capture import KeyedBoard

HAND_BACK = ["SET_RADIO", "SET_CHANNEL", "STOP"]


def board_on(monkeypatch, dirty: bool) -> KeyedBoard:
    board = KeyedBoard("esp32c6")
    board.values[Command.RADIO_DIRTY] = 1 if dirty else 0
    monkeypatch.setattr(recovery, "_open", lambda port, timeout=30.0: board)
    return board


def test_a_board_left_dirty_gets_its_front_end_handed_back(monkeypatch):
    board = board_on(monkeypatch, dirty=True)
    assert recovery.ensure_wifi_ready("COM_UNUSED", settle=0.0)
    sent = board.sequence()
    assert sent[sent.index("RADIO_DIRTY") + 1:] == HAND_BACK
    assert "RADIO_POWER_CYCLE" not in sent


def test_the_hand_back_starts_802154_before_stopping_it(monkeypatch):
    """SET_CHANNEL is what starts the radio on the C6; a STOP alone finds it
    stopped already and does nothing."""
    board = board_on(monkeypatch, dirty=True)
    recovery.ensure_wifi_ready("COM_UNUSED", settle=0.0)
    radio = [p for _, c, p in board.written if c == Command.SET_RADIO]
    assert radio and radio[0][1] == 0          # Radio.IEEE802154


def test_a_clean_board_is_left_alone(monkeypatch):
    board = board_on(monkeypatch, dirty=False)
    assert not recovery.ensure_wifi_ready("COM_UNUSED", settle=0.0)
    assert board.sequence() == ["RADIO_DIRTY"]


def test_hand_back_on_its_own(monkeypatch):
    """For a receiver found deaf with the flag clear, and for --recover."""
    board = board_on(monkeypatch, dirty=False)
    recovery.hand_back("COM_UNUSED", settle=0.0)
    assert board.sequence() == HAND_BACK
