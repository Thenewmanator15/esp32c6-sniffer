"""A Wi-Fi receiver that has latched deaf is power-cycled before the capture.

The ESP32-C6's Wi-Fi receiver latches deaf -- for minutes or hours, and not
only after the 802.15.4 radio has run -- and a deaf capture is an empty one
with no error: indistinguishable from a quiet channel until someone notices
the file is empty. Only power-gating the radio domain clears it. On
2026-09-25 a scan came back empty with the 802.15.4 flag reading clear, so
the check the session already made did not fire.

So when the receiver should be hearing beacons -- management frames pass the
filter, and access points beacon about ten times a second -- and hears
nothing at all for a few seconds after the capture starts, the session
power-cycles the board once and starts again.
"""

import time

from esp32c6_sniffer import capture
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Command, FrameFilter, Radio
from esp32c6_sniffer.framing import FrameType, encode_frame

from test_ble_keys_capture import KeyedBoard
from test_capture import wifi_payload


class WifiBoard(KeyedBoard):
    """Hears `heard` frames once the capture starts, or nothing at all. A
    Wi-Fi capture starts on SET_CHANNEL; there is no START."""

    def __init__(self, heard: int = 0):
        super().__init__("esp32c6")
        if heard:
            self.after[Command.SET_CHANNEL] = [[bytes(24)] * heard] * 4

    def read(self, n=1):
        # As a port does: an empty read waits out its timeout.
        if not self.rx:
            time.sleep(0.01)
        return super().read(n)

    def packet(self, body: bytes) -> None:
        self.rx += encode_frame(FrameType.PACKET, self.seq,
                                wifi_payload(body, len(body)))
        self.seq += 1


def open_wifi(monkeypatch, *boards, frame_filter=None):
    ports = iter(boards)
    cycles = []
    monkeypatch.setattr(capture, "WIFI_DEAF_S", 0.3)
    monkeypatch.setattr(capture, "ensure_wifi_ready", lambda port: False)
    monkeypatch.setattr(capture, "power_cycle", cycles.append)
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: next(ports))
    session = CaptureSession("COM_UNUSED", channel=6, radio=Radio.WIFI,
                             frame_filter=frame_filter)
    session.open()
    return session, cycles


def test_a_deaf_receiver_is_power_cycled_and_the_capture_hears(monkeypatch):
    deaf, hearing = WifiBoard(), WifiBoard(heard=3)
    session, cycles = open_wifi(monkeypatch, deaf, hearing)
    assert cycles == ["COM_UNUSED"]
    assert deaf.closed and session.power_cycled_for_deafness
    records = session.records()
    assert len([next(records) for _ in range(3)]) == 3


def test_a_receiver_that_hears_is_left_alone_and_loses_nothing(monkeypatch):
    """The frames the check heard are the capture's first frames."""
    board = WifiBoard(heard=2)
    session, cycles = open_wifi(monkeypatch, board)
    assert cycles == [] and not session.power_cycled_for_deafness
    records = session.records()
    assert len([next(records) for _ in range(2)]) == 2


def test_no_check_when_the_filter_keeps_beacons_out(monkeypatch):
    """With management frames filtered out a quiet channel is silent for
    real, and power-cycling it would cost seconds every time."""
    monkeypatch.setattr(capture, "WIFI_DEAF_S", 5.0)
    started = time.monotonic()
    session, cycles = open_wifi(monkeypatch, WifiBoard(),
                                frame_filter=FrameFilter.DATA)
    assert cycles == []
    assert time.monotonic() - started < 1.0


def test_a_quiet_channel_in_a_busy_band_is_not_power_cycled(monkeypatch):
    """Channel 14 is silent here for real: opening a capture on it
    power-cycled the board for nothing, 15 s to open. A passive scan -- it
    transmits nothing -- tells a quiet channel from a deaf receiver, which
    finds nothing anywhere. It takes the radio out of capture mode, so the
    capture is started again after it."""
    board = WifiBoard()
    board.values[Command.WIFI_SCAN] = 8
    session, cycles = open_wifi(monkeypatch, board)
    assert cycles == [] and not session.power_cycled_for_deafness
    after = board.sequence()[board.sequence().index("SET_CHANNEL"):]
    assert after[1:] == ["STOP", "WIFI_SCAN", "SET_RADIO", "SET_ANTENNA",
                         "SET_CHANNEL"]


def test_a_receiver_still_deaf_after_the_cycle_is_cycled_only_once(monkeypatch):
    """The capture goes ahead, and the stall counters say it is deaf."""
    session, cycles = open_wifi(monkeypatch, WifiBoard(), WifiBoard())
    assert cycles == ["COM_UNUSED"]
