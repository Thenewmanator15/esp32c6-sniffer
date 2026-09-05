"""Checks the plugin speaks the protocol Wireshark expects.

Runs it as a subprocess, exactly as Wireshark does, rather than importing it.
A plugin that works when imported but fails when executed is still broken.
"""

import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"
INTERFACE = "esp32c6-802154"


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
    """Wi-Fi and BLE must not appear until their milestones land.

    An interface that shows up in Wireshark and then fails is worse than one
    that is not there yet.
    """
    out = _run("--extcap-interfaces")
    assert "esp32c6-wifi" not in out
    assert "esp32c6-ble" not in out


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
         "--extcap-interface", "esp32c6-wifi"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode != 0
    assert "unknown interface" in result.stderr.lower()


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
