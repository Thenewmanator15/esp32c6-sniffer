"""Scanning, and the reload button that puts the result in the channel list.

The scan itself needs the board, so what is tested here is everything around
it: the counting, and the plugin's handling of Wireshark's reload call. The
one fault this found in practice is recorded in test_a_deaf_receiver_... below
-- it is the reason the recovery call exists in scan.py.
"""

import importlib.util
import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from esp32c6_sniffer.apscan import AccessPoint
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
