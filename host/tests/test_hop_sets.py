"""Channel hopping, which is now per radio rather than Wi-Fi only.

802.15.4 needs it more than Wi-Fi does. Wi-Fi beacons every 100 ms on a
handful of channels, so a survey finds the traffic in seconds. 802.15.4 has
sixteen channels, nothing that announces itself, and a quiet capture is
indistinguishable from the wrong channel: measured on this bench, channel 11
gave 2 frames in 15 s while channel 25 gave 135.

Verified live: a 40 s capture hopping the Zigbee preferred set visited
channels 11, 15 and 25 in one file.
"""

import importlib.util
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_hop", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


def test_each_radio_hops_within_its_own_channel_range():
    """A hop set from the wrong radio would retune to a channel that either
    does not exist or is a different frequency entirely -- 11 to 14 are valid
    in both and mean different things."""
    for interface, (low, high) in (
        (plugin.WIFI_INTERFACE, (plugin.WIFI_CHANNEL_MIN,
                                 plugin.WIFI_CHANNEL_MAX)),
        (plugin.INTERFACE, (plugin.CHANNEL_MIN, plugin.CHANNEL_MAX)),
    ):
        for key, channels in plugin.HOP_SETS[interface].items():
            if channels is None:
                continue
            assert channels, f"{interface} set {key} is empty"
            for channel in channels:
                assert low <= channel <= high, (interface, key, channel)


def test_zero_means_off_for_every_radio():
    for interface, sets in plugin.HOP_SETS.items():
        assert sets[0] is None, interface


def test_ble_has_no_hop_sets():
    """The controller rotates the three advertising channels itself, so a hop
    would be a promise the radio cannot keep."""
    assert plugin.BLE_INTERFACE not in plugin.HOP_SETS


def test_the_zigbee_preferred_set_is_the_documented_one():
    """11, 15, 20 and 25. A Zigbee network almost always sits on one of these,
    so sweeping them finds one in a quarter of the time a full sweep takes."""
    assert plugin.HOP_SETS[plugin.INTERFACE][1] == (11, 15, 20, 25)


def test_the_full_sets_cover_every_channel():
    wifi = plugin.HOP_SETS[plugin.WIFI_INTERFACE][2]
    assert wifi == tuple(range(1, 14))
    zigbee = plugin.HOP_SETS[plugin.INTERFACE][2]
    assert zigbee == tuple(range(plugin.CHANNEL_MIN, plugin.CHANNEL_MAX + 1))


@pytest.mark.parametrize("interface", ["esp32c6-802154", "esp32c6-wifi"])
def test_the_option_is_offered_where_a_set_exists(interface, capsys):
    plugin.print_config(interface)
    out = capsys.readouterr().out
    assert "call=--hop}" in out, interface
    assert "call=--hop-dwell}" in out, interface


def test_the_option_is_not_offered_for_ble(capsys):
    plugin.print_config("esp32c6-ble")
    out = capsys.readouterr().out
    assert "call=--hop}" not in out


def test_the_dwell_default_differs_by_radio(capsys):
    """Wi-Fi can use a short dwell because beacons arrive every 100 ms.
    802.15.4 has nothing periodic to catch, so a dwell that short would sweep
    past ordinary traffic without seeing any of it."""
    plugin.print_config("esp32c6-wifi")
    wifi = capsys.readouterr().out
    plugin.print_config("esp32c6-802154")
    zigbee = capsys.readouterr().out

    def dwell(text):
        line = next(l for l in text.splitlines() if "call=--hop-dwell}" in l)
        return int(line.split("{default=")[1].split("}")[0])

    assert dwell(zigbee) > dwell(wifi)
