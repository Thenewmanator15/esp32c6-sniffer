"""Scanning, and the reload button that puts the result in the channel list.

The scan itself needs the board, so what is tested here is everything around
it: the counting, and the plugin's handling of Wireshark's reload call. The
one fault this found in practice is recorded in test_a_deaf_receiver_... below
-- it is the reason the recovery call exists in scan.py.
"""

import importlib.util
import io
import struct
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from esp32c6_sniffer.apscan import AccessPoint
from esp32c6_sniffer.control import Command
from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.scan import busiest_channels

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_scan", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


def ap(channel, ssid="net", rssi=-50):
    return AccessPoint(ssid=ssid, bssid="11:22:33:44:55:66", channel=channel,
                       rssi_dbm=rssi, authmode=3)


def test_counting_groups_by_channel():
    counts = busiest_channels([ap(6), ap(6), ap(11), ap(1)])
    assert counts == {6: 2, 11: 1, 1: 1}


def test_counting_nothing_is_an_empty_map_not_a_zero_for_every_channel():
    assert busiest_channels([]) == {}


def config(interface, reload_option=None, scan=None):
    """Captures what print_config writes, with the scan stubbed."""
    if scan is not None:
        original = plugin.scanned_channel_labels
        plugin.scanned_channel_labels = scan
    try:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            plugin.print_config(interface, reload_option, "COM_UNUSED")
        return buffer.getvalue()
    finally:
        if scan is not None:
            plugin.scanned_channel_labels = original


def test_the_channel_list_is_plain_without_a_reload():
    out = config("esp32c6-wifi")
    assert "{display=6 (2437 MHz)}" in out


def test_a_reload_annotates_the_channels():
    out = config("esp32c6-wifi", "channel",
                 scan=lambda _i, _p: {6: "  [3 networks]"})
    assert "{display=6 (2437 MHz)  [3 networks]}" in out


def test_the_reload_name_arrives_without_dashes():
    """Wireshark passes the option's call value stripped of its leading
    dashes -- 'channel', not '--channel'. Comparing against the dashed form
    silently never matched, so the button appeared to do nothing."""
    called = []
    config("esp32c6-wifi", "--channel",
           scan=lambda i, p: called.append(1) or {})
    assert not called, "matched the dashed form, which Wireshark never sends"

    config("esp32c6-wifi", "channel", scan=lambda i, p: called.append(1) or {})
    assert called


def test_reloading_a_different_option_does_not_scan():
    """A reload of some other option must not hold the port for ten seconds
    and must not replace the channel list."""
    called = []
    config("esp32c6-wifi", "snaplen", scan=lambda i, p: called.append(1) or {})
    assert not called


def test_only_wifi_reloads():
    """802.15.4 has no scan. Offering the button there would be a promise the
    radio cannot keep."""
    called = []
    config("esp32c6-802154", "channel",
           scan=lambda i, p: called.append(1) or {})
    assert not called
    assert "reload=true" not in config("esp32c6-802154")
    assert "reload=true" in config("esp32c6-wifi")


def test_a_failed_scan_leaves_a_usable_list():
    """An empty dropdown, because the board was busy, is worse than an
    unannotated one: the channel becomes unselectable."""
    def failing(_interface, _port):
        return {c: "  [scan failed: SerialException]" for c in range(1, 15)}

    out = config("esp32c6-wifi", "channel", scan=failing)
    assert out.count("value {arg=1}") == 14
    assert "scan failed" in out


def test_a_deaf_receiver_would_report_an_empty_band_not_an_error():
    """Why scan.py power-cycles before scanning, rather than trusting the
    scan to fail if the front end is deaf.

    Using the 802.15.4 radio leaves the Wi-Fi receiver deaf until the RF
    domain is power-gated. A scan then COMPLETES and reports zero access
    points, which is indistinguishable from an empty band. Measured: every
    channel came back "quiet" on a band with four networks on it.
    """
    import inspect

    from esp32c6_sniffer import scan

    source = inspect.getsource(scan.scan_access_points)
    assert "ensure_wifi_ready" in source
    # Before the port is opened, or it cannot power-cycle.
    assert source.index("ensure_wifi_ready") < source.index("serial.Serial")


def ap_record(channel: int, ssid: bytes = b"net") -> bytes:
    return (struct.pack("<bBBB", -50, channel, 3, len(ssid))
            + bytes.fromhex("112233445566") + ssid)


class ScanningBoard:
    """Answers SET_RADIO, and answers WIFI_SCAN with `sent` records and a
    reply counting `counted` -- what the ESP32-C6 did when it fetched the
    results four at a time: counted 7, sent 4."""

    def __init__(self, counted: int, sent: int):
        self.counted, self.sent = counted, sent
        self.rx = bytearray()
        self.seq = 0

    def _frame(self, ftype, payload):
        self.rx += encode_frame(ftype, self.seq, payload)
        self.seq += 1

    def write(self, data):
        for frame in StreamParser().feed(bytes(data)):
            command, _ = struct.unpack_from("<BI", frame.payload)
            value = 0
            if command == Command.WIFI_SCAN:
                for i in range(self.sent):
                    self._frame(FrameType.AP_RECORD, ap_record(1 + i))
                value = self.counted
            self._frame(FrameType.CONTROL_REPLY,
                        struct.pack("<BBI", command, 0, value))
        return len(data)

    def read(self, n=1):
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def flush(self):
        pass

    def set_buffer_size(self, **_):
        pass

    def close(self):
        pass


def run_scan(monkeypatch, board):
    from esp32c6_sniffer import scan

    monkeypatch.setattr(scan, "ensure_wifi_ready", lambda port: False)
    monkeypatch.setattr(scan.serial, "Serial", lambda *a, **k: board)
    return scan.scan_access_points("COM_UNUSED", settle=0.0, timeout=2.0)


def test_a_scan_returns_every_access_point_the_board_counted(monkeypatch):
    assert len(run_scan(monkeypatch, ScanningBoard(counted=7, sent=7))) == 7


def test_a_scan_that_lost_records_says_so(monkeypatch):
    """The board counted 7 and sent 4, and the four came back as the whole
    band. The count was in the reply all along."""
    from esp32c6_sniffer.scan import IncompleteScan

    with pytest.raises(IncompleteScan, match="counted 7 .* sent 4") as caught:
        run_scan(monkeypatch, ScanningBoard(counted=7, sent=4))
    assert len(caught.value.found) == 4
