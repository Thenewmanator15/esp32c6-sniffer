"""Channel hopping, which is now per radio rather than Wi-Fi only.

802.15.4 needs it more than Wi-Fi does. Wi-Fi beacons every 100 ms on a
handful of channels, so a survey finds the traffic in seconds. 802.15.4 has
sixteen channels, nothing that announces itself, and a quiet capture is
indistinguishable from the wrong channel: measured on this bench, channel 11
gave 2 frames in 15 s while channel 25 gave 135.

Verified live: a 40 s capture hopping the Zigbee preferred set visited
channels 11, 15 and 25 in one file.

The sets are looked up by RADIO, not by interface name. They were once keyed
by the ESP32-C6's bare names, so hopping existed only while that board was the
only one attached: plug in a second board and Wireshark names every interface
with its port, the option vanished from the dialog, and the capture refused
the set it had just offered. The nRF54L15 never had it at all. Two boards
sweeping half the band each -- the fastest way to find a quiet network -- was
the one setup that could not work.
"""

import importlib.util
import re
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_hop", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()

#: Every form an interface name takes: alone, and port-qualified once a second
#: board is attached. Both boards for 802.15.4; the C6 alone for Wi-Fi.
HOPPING_INTERFACES = [
    "esp32c6-802154", "esp32c6-802154@COM3",
    "nrf54l15-802154", "nrf54l15-802154@COM4",
    "esp32c6-wifi", "esp32c6-wifi@COM3",
]


def offered_hop_values(interface, capsys):
    plugin.print_config(interface)
    out = capsys.readouterr().out
    return out, {int(v) for v in re.findall(r"value \{arg=5\}\{value=(\d+)\}", out)}


def test_each_radio_hops_within_its_own_channel_range():
    """A hop set from the wrong radio would retune to a channel that either
    does not exist or is a different frequency entirely -- 11 to 14 are valid
    in both and mean different things."""
    for interface, (low, high) in (
        ("esp32c6-wifi", (plugin.WIFI_CHANNEL_MIN, plugin.WIFI_CHANNEL_MAX)),
        ("esp32c6-802154", (plugin.CHANNEL_MIN, plugin.CHANNEL_MAX)),
    ):
        for key, channels in plugin.hop_sets(interface).items():
            if channels is None:
                continue
            assert channels, f"{interface} set {key} is empty"
            for channel in channels:
                assert low <= channel <= high, (interface, key, channel)


@pytest.mark.parametrize("interface", HOPPING_INTERFACES)
def test_zero_means_off_for_every_interface(interface):
    assert plugin.hop_sets(interface)[0] is None


@pytest.mark.parametrize("interface", ["esp32c6-ble", "nrf54l15-ble",
                                       "nrf54l15-ble@COM4"])
def test_ble_has_no_hop_sets(interface, capsys):
    """The controller rotates the three advertising channels itself, so a hop
    would be a promise the radio cannot keep."""
    assert plugin.hop_sets(interface) == {0: None}
    out, _ = offered_hop_values(interface, capsys)
    assert "call=--hop}" not in out


def test_the_zigbee_preferred_set_is_the_documented_one():
    """11, 15, 20 and 25. A Zigbee network almost always sits on one of these,
    so sweeping them finds one in a quarter of the time a full sweep takes."""
    assert plugin.hop_sets("esp32c6-802154")[1] == (11, 15, 20, 25)


def test_the_full_sets_cover_every_channel():
    assert plugin.hop_sets("esp32c6-wifi")[2] == tuple(range(1, 14))
    assert plugin.hop_sets("esp32c6-802154")[2] == tuple(
        range(plugin.CHANNEL_MIN, plugin.CHANNEL_MAX + 1))


def test_the_two_halves_split_the_band_between_two_boards():
    """One board on each half sweeps all sixteen channels in the time eight
    take, and neither spends a dwell on a channel the other has covered."""
    sets = plugin.hop_sets("nrf54l15-802154@COM4")
    low, high = sets[3], sets[4]
    assert low == tuple(range(11, 19))
    assert high == tuple(range(19, 27))
    assert not set(low) & set(high)
    assert set(low) | set(high) == set(sets[2])
    assert len(low) == len(high)


@pytest.mark.parametrize("interface", HOPPING_INTERFACES)
def test_the_option_is_offered_on_every_board_and_port_form(interface, capsys):
    out, _ = offered_hop_values(interface, capsys)
    assert "call=--hop}" in out, interface
    assert "call=--hop-dwell}" in out, interface


@pytest.mark.parametrize("interface", HOPPING_INTERFACES)
def test_the_capture_accepts_exactly_what_the_dialog_offers(interface, capsys):
    """An offered set the capture then refuses is worse than no option: it
    fails only after Wireshark has committed to the capture."""
    _, offered = offered_hop_values(interface, capsys)
    assert offered == set(plugin.hop_sets(interface)), interface


def test_the_dwell_default_differs_by_radio(capsys):
    """Wi-Fi can use a short dwell because beacons arrive every 100 ms.
    802.15.4 has nothing periodic to catch, so a dwell that short would sweep
    past ordinary traffic without seeing any of it."""
    plugin.print_config("esp32c6-wifi")
    wifi = capsys.readouterr().out
    plugin.print_config("nrf54l15-802154@COM4")
    zigbee = capsys.readouterr().out

    def dwell(text):
        line = next(l for l in text.splitlines() if "call=--hop-dwell}" in l)
        return int(line.split("{default=")[1].split("}")[0])

    assert dwell(zigbee) > dwell(wifi)
