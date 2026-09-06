"""Checks the plugin speaks the protocol Wireshark expects.

Runs it as a subprocess, exactly as Wireshark does, rather than importing it.
A plugin that works when imported but fails when executed is still broken.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"
INTERFACE = "esp32c6-802154"
WIFI_INTERFACE = "esp32c6-wifi"
BLE_INTERFACE = "esp32c6-ble"


def _run(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, str(PLUGIN), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"exit {result.returncode}\nstdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    return result.stdout


def test_plugin_file_exists():
    assert PLUGIN.is_file(), f"plugin missing at {PLUGIN}"


def test_lists_the_802154_interface():
    out = _run("--extcap-interfaces")
    assert f"interface {{value={INTERFACE}}}" in out


def test_declares_the_extcap_version_line():
    """Wireshark needs the extcap header line to recognise the plugin."""
    out = _run("--extcap-interfaces")
    assert out.startswith("extcap {version=")


def test_does_not_advertise_unimplemented_radios():
    """BLE must not appear until its milestone lands.

    An interface that shows up in Wireshark and then fails is worse than one
    that is not there yet. Wi-Fi used to be on this list and has now landed,
    so it is asserted present instead.
    """
    out = _run("--extcap-interfaces")
    # BLE has since landed and is asserted present below; nothing is left on
    # the not-yet list, so this now guards against inventing one.
    assert "esp32c6-thread" not in out


def test_lists_the_wifi_interface():
    out = _run("--extcap-interfaces")
    assert f"interface {{value={WIFI_INTERFACE}}}" in out


def test_reports_the_radiotap_linktype_for_wifi():
    out = _run("--extcap-dlts", "--extcap-interface", WIFI_INTERFACE)
    assert "number=127" in out
    assert "IEEE802_11_RADIOTAP" in out


def test_each_interface_reports_only_its_own_linktype():
    """A capture written with the wrong link type decodes as noise."""
    tap = _run("--extcap-dlts", "--extcap-interface", INTERFACE)
    radiotap = _run("--extcap-dlts", "--extcap-interface", WIFI_INTERFACE)
    assert "number=127" not in tap
    assert "number=283" not in radiotap


def test_wifi_config_offers_only_wifi_channels():
    out = _run("--extcap-config", "--extcap-interface", WIFI_INTERFACE)
    assert "{default=6}" in out
    assert "value {arg=1}{value=1}" in out
    assert "value {arg=1}{value=14}" in out
    # 26 is an 802.15.4 channel and must not be offered here.
    assert "value {arg=1}{value=26}" not in out


def test_toolbar_channel_values_are_radio_prefixed():
    """Channels 11-14 exist in both radios and mean different frequencies.

    A bare number in a shared toolbar is ambiguous, so a mis-click would
    silently retune to the wrong band instead of being rejected.
    """
    out = _run("--extcap-interfaces")
    assert "{value=z11}" in out
    assert "{value=w11}" in out


def test_toolbar_scopes_channels_to_a_named_interface():
    out = _run("--extcap-interfaces", "--extcap-interface", WIFI_INTERFACE)
    assert "{value=w6}" in out
    assert "{value=z25}" not in out


def test_reports_the_tap_linktype():
    out = _run("--extcap-dlts", "--extcap-interface", INTERFACE)
    assert "number=283" in out
    assert "IEEE802_15_4_TAP" in out


def test_offers_port_channel_and_antenna_options():
    out = _run("--extcap-config", "--extcap-interface", INTERFACE)
    assert "call=--port" in out
    assert "call=--channel" in out
    assert "call=--antenna" in out


def test_offers_no_baud_rate_option():
    """A USB CDC virtual port has no physical line rate.

    Other projects expose a baud setting inherited from bridge-chip designs.
    Here the value is discarded, so offering it would mislead.
    """
    out = _run("--extcap-config", "--extcap-interface", INTERFACE)
    assert "baud" not in out.lower()


def test_every_valid_channel_is_selectable_with_its_frequency():
    out = _run("--extcap-config", "--extcap-interface", INTERFACE)
    for channel in range(11, 27):
        assert f"{{arg=1}}{{value={channel}}}" in out
    assert "2405 MHz" in out
    assert "2480 MHz" in out


def test_both_antennas_are_selectable():
    out = _run("--extcap-config", "--extcap-interface", INTERFACE)
    assert "{arg=2}{value=0}" in out
    assert "{arg=2}{value=1}" in out


def test_unknown_interface_is_rejected():
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--extcap-dlts",
         "--extcap-interface", "esp32c6-thread"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "unknown interface" in result.stderr.lower()


def test_wifi_channel_out_of_range_is_rejected():
    """26 is a valid 802.15.4 channel and an invalid Wi-Fi one."""
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture",
         "--extcap-interface", WIFI_INTERFACE,
         "--fifo", _throwaway_fifo(), "--channel", "26"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "outside 1-14" in result.stderr


def test_capture_without_fifo_fails_loudly():
    """Wireshark surfaces stderr, so failures must be visible there."""
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture",
         "--extcap-interface", INTERFACE],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "fifo" in result.stderr.lower()


@pytest.mark.parametrize("channel", ["10", "27"])
def test_capture_rejects_an_out_of_range_channel(channel):
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture",
         "--extcap-interface", INTERFACE, "--fifo", "nul",
         "--channel", channel],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "channel" in result.stderr.lower()


def test_declares_toolbar_controls_on_both_lines():
    """The control bitfield must appear on the extcap AND interface lines.

    Declaring controls only in --extcap-config does not make Wireshark create
    the control pipes, and the failure is silent.
    """
    out = _run("--extcap-interfaces")
    lines = out.splitlines()
    extcap_line = next(l for l in lines if l.startswith("extcap "))
    iface_line = next(l for l in lines if l.startswith("interface "))
    assert "{control=" in extcap_line
    assert "{control=" in iface_line


def test_offers_a_channel_selector_control():
    out = _run("--extcap-interfaces")
    assert "control {number=0}{type=selector}" in out
    for channel in (11, 26):
        assert f"value {{control=0}}{{value=z{channel}}}" in out


def test_offers_a_logger_control():
    out = _run("--extcap-interfaces")
    assert "{role=logger}" in out


def test_channel_remains_a_config_option_too():
    """tshark has no toolbar, so nothing essential may live only there."""
    out = _run("--extcap-config", "--extcap-interface", INTERFACE)
    assert "call=--channel" in out


def test_wifi_offers_throughput_controls():
    """A busy 802.11 channel produces far more than the link carries, so these
    are throughput controls rather than preferences."""
    out = _run("--extcap-config", "--extcap-interface", WIFI_INTERFACE)
    assert "{call=--snaplen}" in out
    assert "{call=--filter}" in out


def test_wifi_offers_channel_hopping():
    out = _run("--extcap-config", "--extcap-interface", WIFI_INTERFACE)
    assert "{call=--hop}" in out
    assert "{call=--hop-dwell}" in out
    assert "1, 6, 11" in out


def test_802154_does_not_offer_wifi_only_options():
    """Offering a control the board would silently ignore is worse than not
    offering it."""
    out = _run("--extcap-config", "--extcap-interface", INTERFACE)
    assert "{call=--snaplen}" not in out
    assert "{call=--filter}" not in out
    assert "{call=--hop}" not in out


def test_out_of_range_snaplen_is_rejected():
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture",
         "--extcap-interface", WIFI_INTERFACE,
         "--fifo", _throwaway_fifo(), "--channel", "6", "--snaplen", "9000"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "snaplen" in result.stderr.lower()


def test_unknown_hop_set_is_rejected():
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture",
         "--extcap-interface", WIFI_INTERFACE,
         "--fifo", _throwaway_fifo(), "--channel", "6", "--hop", "99"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "hop" in result.stderr.lower()


def _throwaway_fifo() -> str:
    """A path inside pytest's temp area.

    These cases are meant to fail before the pipe is ever opened, but a bare
    relative name means that when one does not, the plugin creates a file in
    whatever directory the tests were run from. One escaped and was committed.
    """
    return str(Path(tempfile.gettempdir()) / "esp32c6-selftest-fifo")


def _run_expect_failure(*args: str):
    result = subprocess.run(
        [sys.executable, str(PLUGIN), *args],
        capture_output=True, text=True, timeout=30,
    )
    return result


def test_negative_snaplen_is_rejected():
    r = _run_expect_failure("--capture", "--extcap-interface", WIFI_INTERFACE,
                            "--fifo", _throwaway_fifo(), "--channel", "6",
                            "--snaplen", "-1")
    assert r.returncode != 0


def test_negative_hop_dwell_does_not_spin():
    """A negative dwell would make the hop thread never sleep, pinning a core
    and flooding the board with retunes."""
    r = _run_expect_failure("--capture", "--extcap-interface", WIFI_INTERFACE,
                            "--fifo", _throwaway_fifo(), "--channel", "6",
                            "--hop", "1", "--hop-dwell", "-5")
    assert r.returncode != 0, "a negative dwell was accepted"


def test_unwritable_csi_path_fails_before_the_capture_starts():
    """Failing after Wireshark has started showing packets is much worse than
    failing immediately."""
    r = _run_expect_failure("--capture", "--extcap-interface", WIFI_INTERFACE,
                            "--fifo", _throwaway_fifo(), "--channel", "6",
                            "--csi", "/nonexistent-directory/x.csv")
    assert r.returncode != 0


def test_unknown_arguments_are_ignored_not_fatal():
    """Wireshark passes options this plugin never declared; refusing them
    would make the interface unusable."""
    out = _run("--extcap-interfaces", "--some-future-option", "value")
    assert "interface {value=" in out


def test_every_interface_declares_a_distinct_link_type():
    """The pcap header and the DLT Wireshark is told must agree, and each
    radio needs its own. A hard-coded two-way choice silently wrote BLE
    records labelled as 802.15.4 and Wireshark dissected none of them."""
    seen = {}
    for name in ("esp32c6-802154", WIFI_INTERFACE, BLE_INTERFACE):
        out = _run("--extcap-dlts", "--extcap-interface", name)
        number = out.split("{number=")[1].split("}")[0]
        assert number not in seen, f"{name} reuses DLT {number} from {seen[number]}"
        seen[number] = name
    assert set(seen) == {"283", "127", "201"}


def test_ble_interface_offers_no_channel():
    """The controller rotates the advertising channels itself, so offering a
    channel would be a promise the toolbar could not keep."""
    out = _run("--extcap-config", "--extcap-interface", BLE_INTERFACE)
    assert "{call=--channel}" not in out
    assert "{call=--ble-interval}" in out


def test_ble_channel_selection_is_rejected():
    r = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture",
         "--extcap-interface", BLE_INTERFACE, "--fifo", _throwaway_fifo(),
         "--channel", "6", "--port", "COM_UNUSED"],
        capture_output=True, text=True, timeout=30,
    )
    # It must not silently accept a channel it cannot honour.
    assert r.returncode != 0


def test_ble_toolbar_has_no_empty_channel_control():
    """BLE has no channel: the controller rotates the three advertising
    channels itself. Declaring the control anyway gave a BLE capture an empty
    Channel dropdown in the toolbar, contradicting the refusal the config path
    already makes."""
    out = _run("--extcap-interfaces", "--extcap-interface", BLE_INTERFACE)
    assert "display=Channel}" not in out
    assert "value {control=0}" not in out


def test_the_other_radios_still_offer_channels():
    for interface, count in ((INTERFACE, 16), (WIFI_INTERFACE, 14)):
        out = _run("--extcap-interfaces", "--extcap-interface", interface)
        assert "display=Channel}" in out, interface
        assert out.count("value {control=0}") == count, interface


def test_a_capture_filter_is_refused_rather_than_ignored():
    """Wireshark shows a capture-filter box for extcap interfaces and passes
    whatever is typed. It used to be swallowed, so the capture ran unfiltered
    and looked fine -- the worst way to handle an instruction."""
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture", "--fifo", "unused",
         "--extcap-interface", BLE_INTERFACE,
         "--extcap-capture-filter", "type mgt"],
        capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "capture filter cannot be applied" in result.stderr
    # It must say what to use instead, not merely refuse.
    assert "Frame types" in result.stderr or "display filter" in result.stderr
