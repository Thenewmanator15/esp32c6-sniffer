"""Several boards at once, which is the only way to capture two radios at once.

The C6 has a single 2.4 GHz front end, so one board can do Zigbee or Wi-Fi and
never both. Two boards can, and that is the whole point of naming interfaces
after the board they belong to.

The naming has to stay bare when there is only one board, because Wireshark
saves capture options against the interface name: renaming the interface for
everybody would silently drop the snapshot length, channel and filter that
existing users had configured.
"""

import importlib.util
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_multi", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()

RADIOS = {"esp32c6-802154", "esp32c6-wifi", "esp32c6-ble"}


def with_ports(monkeypatch, ports):
    monkeypatch.setattr(plugin, "find_board_ports", lambda: list(ports))


def test_one_board_keeps_the_bare_names(monkeypatch):
    """Anything else moves every saved per-interface option."""
    with_ports(monkeypatch, ["COM3"])
    values = {value for value, _display in plugin.board_interfaces()}
    assert values == RADIOS


def test_no_board_still_advertises_the_interfaces(monkeypatch):
    """Wireshark asks what exists before anything is plugged in, and an
    interface that vanishes when the board is unplugged cannot be selected in
    advance."""
    with_ports(monkeypatch, [])
    values = {value for value, _display in plugin.board_interfaces()}
    assert values == RADIOS


def test_two_boards_give_one_set_each(monkeypatch):
    with_ports(monkeypatch, ["COM3", "COM7"])
    entries = plugin.board_interfaces()
    values = {value for value, _display in entries}
    assert values == {f"{radio}@{port}"
                      for radio in RADIOS for port in ("COM3", "COM7")}
    assert len(entries) == 6


def test_two_boards_are_told_apart_in_the_display_name(monkeypatch):
    """Six interfaces of which two pairs differ only by port would be
    unusable in the Wireshark list."""
    with_ports(monkeypatch, ["COM3", "COM7"])
    displays = [display for _value, display in plugin.board_interfaces()]
    assert len(set(displays)) == 6
    assert all("COM3" in d or "COM7" in d for d in displays)


@pytest.mark.parametrize("name,radio,port", [
    ("esp32c6-wifi", "esp32c6-wifi", None),
    ("esp32c6-wifi@COM7", "esp32c6-wifi", "COM7"),
    ("esp32c6-802154@/dev/ttyACM1", "esp32c6-802154", "/dev/ttyACM1"),
])
def test_an_interface_name_splits_into_radio_and_board(name, radio, port):
    assert plugin.split_interface(name) == (radio, port)


def test_a_unix_device_path_survives_the_split():
    """A Linux port is /dev/ttyACM0, which contains no @ but does contain the
    separators one might have reached for first."""
    radio, port = plugin.split_interface("esp32c6-ble@/dev/ttyACM0")
    assert (radio, port) == ("esp32c6-ble", "/dev/ttyACM0")


def test_the_separator_is_not_a_character_a_port_can_contain():
    """If it were, splitting would cut a port name in half."""
    for port in ("COM3", "COM12", "/dev/ttyACM0", "/dev/ttyUSB1",
                 "/dev/cu.usbmodem14201"):
        assert plugin.PORT_SEPARATOR not in port
