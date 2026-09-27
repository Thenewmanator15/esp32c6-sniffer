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


class SilentSession:
    """A receiver that hears nothing, as a deaf one does: records() yields
    nothing until it is asked to stop, as a port read that times out does."""

    def __init__(self, port, **kw):
        import threading
        import types
        self._stop = threading.Event()
        self._serial = types.SimpleNamespace(read=lambda n=1: b"")
        self.stats = object()

    def open(self):
        pass

    def close(self):
        pass

    def request_stop(self):
        self._stop.set()

    def records(self):
        import time
        while not self._stop.is_set():
            time.sleep(0.01)
        return
        yield


def finishes(fn, limit: float) -> list:
    """fn's result, or [] if it was still running after `limit` seconds --
    so a hang fails the test instead of stalling the suite."""
    import threading
    result = []
    thread = threading.Thread(target=lambda: result.append(fn()), daemon=True)
    thread.start()
    thread.join(limit)
    return result


def test_a_deaf_receiver_measures_as_no_frames_rather_than_forever(monkeypatch):
    """The deadline was checked only when a frame arrived, so a receiver
    that heard nothing -- the very state the trial exists to measure, now
    that it measures without the recovery -- kept the trial waiting for
    ever."""
    monkeypatch.setattr(latch_trial, "CaptureSession", SilentSession)
    assert finishes(lambda: latch_trial.count_wifi_frames("COM_UNUSED",
                                                          seconds=0.3), 5.0) == [0]


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_recovery_is_timed_from_when_the_wait_begins():
    """A deaf trial the power-gate did not cure used to end the run: every
    later baseline failed. The receiver came back on its own about twenty
    minutes later, so the trial now waits, and times it."""
    clock = FakeClock()
    readings = iter([0, 0, 4])
    took = latch_trial.await_recovery("COM_UNUSED", lambda port: next(readings),
                                      limit_s=600, poll_s=60,
                                      clock=clock.time, sleep=clock.sleep)
    assert took == 180


def test_a_receiver_still_deaf_at_the_limit_gives_none():
    clock = FakeClock()
    took = latch_trial.await_recovery("COM_UNUSED", lambda port: 0,
                                      limit_s=300, poll_s=60,
                                      clock=clock.time, sleep=clock.sleep)
    assert took is None
    assert clock.now <= 360


def test_a_board_that_does_not_answer_is_not_a_recovery():
    """None from the measure is a board that did not answer, not a zero,
    and not a non-zero either."""
    clock = FakeClock()
    readings = iter([None, None, 2])
    took = latch_trial.await_recovery("COM_UNUSED", lambda port: next(readings),
                                      limit_s=600, poll_s=60,
                                      clock=clock.time, sleep=clock.sleep)
    assert took == 180
