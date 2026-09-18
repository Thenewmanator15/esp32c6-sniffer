"""The BLE self-test checks, driven without a board.

selftest.py needs hardware, which is why nothing else here imports it. These
two checks earn the exception: their whole purpose is to notice a counter
reading zero for the wrong reason, and a check that cannot fire would fail in
exactly the way it exists to catch. Stub sessions are enough, because the
checks only ever read CaptureStats.
"""
import pathlib
import sys

import pytest

# Appended rather than prepended: tools/ holds a trace.py, and putting
# it first would shadow the standard library's module of that name for
# everything the suite imports afterwards.
sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import selftest  # noqa: E402

from esp32c6_sniffer.ble import (  # noqa: E402
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR,
)
from esp32c6_sniffer.capture import CaptureStats  # noqa: E402


class StubSession:
    """Everything the two checks touch, and nothing else."""

    def __init__(self, stats: CaptureStats):
        self.linktype = LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR
        self.stats = stats

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def run(monkeypatch):
    """Runs one check against a stubbed board, returning name -> outcome."""
    def _run(stats: CaptureStats, frames: int, check=None):
        check = check or selftest.check_ble
        monkeypatch.setattr(selftest, "CaptureSession",
                            lambda *a, **k: StubSession(stats))
        monkeypatch.setattr(selftest, "drain",
                            lambda session, seconds, on_record=None: frames)
        selftest.results.clear()
        check("COM_STUB")
        return {name: (outcome, detail)
                for name, outcome, detail in selftest.results}
    return _run


def test_a_board_reporting_nothing_captured_fails(run):
    """The defect this check exists for. Packets reached the host, so a board
    claiming to have captured none is the stats block going unread -- which is
    what it did for a release, while `lossless` stayed true throughout."""
    outcome, detail = run(CaptureStats(), 1500)["BLE drop counters"]
    assert outcome == selftest.FAIL
    assert "not being read" in detail


def test_counters_that_arrived_and_report_no_loss_pass(run):
    stats = CaptureStats(fw_frames_captured=1500, fw_ble_adv_reports=1342)
    assert run(stats, 1500)["BLE drop counters"][0] == selftest.PASS


def test_counters_that_report_loss_fail(run):
    stats = CaptureStats(fw_frames_captured=1500, fw_isr_queue_full=60,
                         fw_link_rejected=40)
    assert run(stats, 1500)["BLE drop counters"][0] == selftest.FAIL


def test_a_quiet_room_skips_before_the_counters_are_judged(run):
    """Nothing advertising is an environment condition. Judging the counters
    then would fail every capture taken in a quiet room."""
    results = run(CaptureStats(), 0)
    assert results["BLE capture"][0] == selftest.SKIP
    assert "BLE drop counters" not in results


def test_refused_periodic_syncs_fail(run):
    """A refusal means the firmware's cap and the controller's configured
    sync count disagree, which is what they did: two against one."""
    stats = CaptureStats(fw_ble_periodic_refused=7)
    outcome, detail = run(stats, 900,
                          selftest.check_ble_periodic)["BLE periodic sync"]
    assert outcome == selftest.FAIL
    assert "disagree" in detail


def test_no_periodic_advertiser_in_range_skips(run):
    """Every room so far. A skip is never counted as a pass."""
    results = run(CaptureStats(), 900, selftest.check_ble_periodic)
    assert results["BLE periodic sync"][0] == selftest.SKIP


def test_a_followed_train_with_no_refusals_passes(run):
    stats = CaptureStats(fw_ble_periodic_seen=3, fw_ble_periodic_synced=1,
                         fw_ble_periodic_reports=88)
    results = run(stats, 900, selftest.check_ble_periodic)
    assert results["BLE periodic sync"][0] == selftest.PASS
