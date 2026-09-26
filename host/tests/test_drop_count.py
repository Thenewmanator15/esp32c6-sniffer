"""How many packets a capture lost, counted once each.

The extcap wrote isr + link_rejected + ringfull + sequence_gaps into the
file's drop count. On the ESP32-C6 one packet its ring refused is all of the
last three at once -- usb_link.c consumes the sequence number before the ring
write, so the host sees a gap too -- and the file said 3 for 1. On the
nRF54L15 a refused frame consumes no sequence number, but link_rejected
counts the packets in a refused batch and ringfull counted the batch again.
"""

import importlib.util
import pathlib
import threading
import time

import pytest

from esp32c6_sniffer import capture, pcapng
from esp32c6_sniffer.boards import BOARDS
from esp32c6_sniffer.capture import CaptureSession, CaptureStats
from esp32c6_sniffer.control import Radio

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def test_a_packet_the_c6_ring_refused_counts_once():
    s = CaptureStats(sequence_gaps=1, fw_link_rejected=1,
                     fw_frames_dropped_ringfull=1)
    assert s.packets_dropped == 1


def test_a_batch_the_nrf_ring_refused_counts_its_packets_once():
    s = CaptureStats(refusals_leave_gaps=False, fw_link_rejected=5,
                     fw_frames_dropped_ringfull=1)
    assert s.packets_dropped == 5


@pytest.mark.parametrize("refusals_leave_gaps", [True, False])
def test_frames_lost_on_the_way_to_the_host_count(refusals_leave_gaps):
    """No refusal explains these: the bridge dropped them, or the USB did."""
    s = CaptureStats(refusals_leave_gaps=refusals_leave_gaps, sequence_gaps=3)
    assert s.packets_dropped == 3


def test_a_refused_frame_that_was_not_a_packet_is_not_a_dropped_packet():
    """A STATS or LINK frame the C6's ring refused is a gap and a ring-full
    drop, and no packet was lost."""
    s = CaptureStats(sequence_gaps=2, fw_link_rejected=1,
                     fw_frames_dropped_ringfull=2)
    assert s.packets_dropped == 1


def test_packets_the_radio_queue_refused_count():
    assert CaptureStats(fw_isr_queue_full=4).packets_dropped == 4


def test_every_board_says_whether_a_refusal_leaves_a_gap():
    assert {b["id"]: b["refusal_leaves_gap"] for b in BOARDS.values()} == {
        "esp32c6": True, "nrf54l15": False}


@pytest.mark.parametrize("board, expected", [("esp32c6", True),
                                             ("nrf54l15", False)])
def test_the_session_counts_by_its_board(board, expected):
    session = CaptureSession("COM_UNUSED", channel=11,
                             radio=Radio.IEEE802154, board=board)
    assert session.stats.refusals_leave_gaps is expected


def test_the_file_records_each_lost_packet_once(monkeypatch):
    spec = importlib.util.spec_from_file_location("extcap_plugin_drops", PLUGIN)
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    recorded = []

    class Recording(pcapng.PcapngWriter):
        def write_statistics(self, **kw):
            recorded.append(kw["dropped"])
            super().write_statistics(**kw)

    class Session:
        def __init__(self, port, **kw):
            self._channel = 11
            self.stats = CaptureStats(sequence_gaps=1, fw_link_rejected=1,
                                      fw_frames_dropped_ringfull=1)
            self.recovered_from_802154 = False
            self.power_cycled_for_deafness = False
            self._stop = threading.Event()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            pass

        def request_stop(self):
            self._stop.set()

        def records(self):
            for _ in range(3):
                time.sleep(0.01)
                yield bytes(40), time.time(), 40

    class Sink:
        def write(self, data):
            return len(data)

        def flush(self):
            pass

        def close(self):
            pass

    monkeypatch.setattr(pcapng, "PcapngWriter", Recording)
    monkeypatch.setattr(capture, "CaptureSession", Session)
    monkeypatch.setattr(plugin, "open", lambda *a, **k: Sink(), raising=False)
    assert plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-interface", "esp32c6-802154",
                        "--port", "COM_UNUSED"]) == 0
    assert recorded and set(recorded) == {1}
