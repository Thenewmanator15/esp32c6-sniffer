"""The latch trial measures the receiver as the treatment left it.

Both of its measures opened the board through code that power-cycles it when
the 802.15.4 flag is set -- scan_access_points() and CaptureSession call
ensure_wifi_ready() -- and the dirty arm is exactly the one that sets it.
Every dirty trial was cured before it was measured, so the replication's
"zero reproductions" never tested that arm. With the flag now kept until a
power cycle, and a silent capture power-cycling too, every arm would be.
"""

import pathlib
import sys

from esp32c6_sniffer import capture, scan
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Radio

from test_scan import ScanningBoard
from test_wifi_deafness import WifiBoard

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import latch_trial  # noqa: E402


def test_a_session_can_be_told_not_to_recover(monkeypatch):
    calls = []
    monkeypatch.setattr(capture, "WIFI_DEAF_S", 0.2)
    monkeypatch.setattr(capture, "ensure_wifi_ready",
                        lambda port: calls.append("flag") or True)
    monkeypatch.setattr(capture, "power_cycle", lambda port: calls.append("cycle"))
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: WifiBoard())
    session = CaptureSession("COM_UNUSED", channel=6, radio=Radio.WIFI,
                             recover=False)
    session.open()
    assert calls == []
    assert not session.recovered_from_802154
    assert not session.power_cycled_for_deafness


def test_a_scan_can_be_told_not_to_recover(monkeypatch):
    calls = []
    monkeypatch.setattr(scan, "ensure_wifi_ready",
                        lambda port: calls.append(port) or True)
    monkeypatch.setattr(scan.serial, "Serial",
                        lambda *a, **k: ScanningBoard(counted=2, sent=2))
    found = scan.scan_access_points("COM_UNUSED", settle=0.0, timeout=2.0,
                                    recover=False)
    assert len(found) == 2 and calls == []


def test_the_trial_measures_without_recovering(monkeypatch):
    seen = []

    def fake_scan(port, **kw):
        seen.append(("scan", kw.get("recover", True)))
        return []

    class FakeSession:
        def __init__(self, port, **kw):
            seen.append(("session", kw.get("recover", True)))
            raise TimeoutError("not a board")

    monkeypatch.setattr(latch_trial, "scan_access_points", fake_scan)
    monkeypatch.setattr(latch_trial, "CaptureSession", FakeSession)
    latch_trial.count_access_points("COM_UNUSED")
    latch_trial.count_wifi_frames("COM_UNUSED", seconds=0.0)
    assert seen == [("scan", False), ("session", False)]
