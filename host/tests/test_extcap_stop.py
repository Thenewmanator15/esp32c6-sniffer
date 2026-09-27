"""Wireshark stops a capture by closing the pipe, and that is a normal stop.

On Windows the next write into the closed pipe fails with EINVAL, not
BrokenPipeError -- an OSError like a serial fault -- and the plugin reported
it as one: exit 1, and on stderr "cannot capture on COM3: [Errno 22] Invalid
argument ... the board did not answer. ... unplug the board and plug it back
in", at the end of every capture. Measured with the real main() driven over
Windows named pipes, closing the read end as Wireshark does: a busy channel
failed on the packet write, a quiet one on closing the file, which flushed
the last statistics block into the pipe that had gone.
"""

import importlib.util
import pathlib
import threading
import time

import pytest

from esp32c6_sniffer import capture
from esp32c6_sniffer.capture import CaptureStats

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


@pytest.fixture
def plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_stop", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ClosedByWireshark:
    """A capture pipe whose reader goes away after `keep` bytes.

    Buffered, as open(fifo, "wb") is, so closing it flushes whatever the last
    writes left behind -- into a pipe that is no longer there."""

    def __init__(self, keep: int):
        self.keep = keep
        self.written = 0
        self.pending = 0

    def _gone(self):
        return self.written >= self.keep

    def write(self, data):
        # As a BufferedWriter does: a small write lands in the buffer, and
        # only one that overflows it reaches the pipe.
        self.pending += len(data)
        if self.pending > 8192:
            self.flush()
        return len(data)

    def flush(self):
        if self._gone() and self.pending:
            raise OSError(22, "Invalid argument")
        self.written += self.pending
        self.pending = 0

    def close(self):
        self.flush()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def fake_session(packets_per_second: float | None):
    class Session:
        def __init__(self, port, **kw):
            self._channel = kw.get("channel", 0)
            self.stats = CaptureStats()
            self._stop = threading.Event()
            self.recovered_from_802154 = False
            self.power_cycled_for_deafness = False
            self.handed_back_for_deafness = False
            self.periodic_needs_extended = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._stop.set()

        def request_stop(self):
            self._stop.set()

        def records(self):
            record = bytes(40)
            while not self._stop.is_set():
                if packets_per_second is None:
                    time.sleep(0.05)            # a read that timed out
                    continue
                time.sleep(1 / packets_per_second)
                self.stats.frames += 1
                yield record, time.time(), len(record)

    return Session


def run(plugin, monkeypatch, capsys, pipe, packets_per_second):
    monkeypatch.setattr(capture, "CaptureSession", fake_session(packets_per_second))
    monkeypatch.setattr(plugin, "open", lambda path, mode="r", *a, **k: pipe,
                        raising=False)
    code = plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-interface", "esp32c6-802154",
                        "--port", "COM_UNUSED"])
    return code, capsys.readouterr().err


def test_closing_the_pipe_mid_stream_is_a_normal_stop(plugin, monkeypatch, capsys):
    pipe = ClosedByWireshark(keep=2000)
    code, err = run(plugin, monkeypatch, capsys, pipe, packets_per_second=1000)
    assert pipe.written >= 2000
    assert (code, err) == (0, "")


def test_closing_the_pipe_on_a_quiet_channel_is_a_normal_stop(plugin, monkeypatch,
                                                                capsys):
    """Nothing is written but the once-a-second statistics, so the heartbeat
    finds the pipe gone, and the file's close finds it again."""
    pipe = ClosedByWireshark(keep=1)
    code, err = run(plugin, monkeypatch, capsys, pipe, packets_per_second=None)
    assert (code, err) == (0, "")


def test_a_board_that_does_not_answer_is_still_reported(plugin, monkeypatch, capsys):
    """The fix must not swallow the serial port's own errors along with the
    pipe's."""
    class Deaf:
        def __init__(self, port, **kw):
            pass

        def __enter__(self):
            raise TimeoutError("no reply to GET_INFO")

        def __exit__(self, *exc):
            pass

    monkeypatch.setattr(capture, "CaptureSession", Deaf)
    monkeypatch.setattr(plugin, "find_board_ports", lambda: [])
    monkeypatch.setattr(plugin, "open", lambda *a, **k: ClosedByWireshark(10**9),
                        raising=False)
    code = plugin.main(["--capture", "--fifo", "FIFO",
                        "--extcap-interface", "esp32c6-802154",
                        "--port", "COM_UNUSED"])
    assert code == 1
    assert "no reply to GET_INFO" in capsys.readouterr().err
