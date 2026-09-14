"""Several boards at once, which is the only way to capture two radios at once.

The C6 has a single 2.4 GHz front end, so one board can do Zigbee or Wi-Fi and
never both. Two boards can, and that is the whole point of naming interfaces
after the board they belong to.

The naming has to stay bare when there is only one board, because Wireshark
saves capture options against the interface name: renaming the interface for
everybody would silently drop the snapshot length, channel and filter that
existing users had configured.

Since a second BOARD TYPE exists, a port no longer implies a radio set. A
C6 interface advertised on the nRF's port would be selectable and would fail
on open, so interfaces are generated per board and matched to that board's
ports.
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

C6_RADIOS = {"esp32c6-802154", "esp32c6-wifi", "esp32c6-ble"}
NRF_RADIOS = {"nrf54l15-802154"}


def with_boards(monkeypatch, found):
    monkeypatch.setattr(plugin, "find_board_ports", lambda: list(found))


def test_one_c6_keeps_the_bare_names(monkeypatch):
    """Byte-identical to the behaviour before a second board type existed.
    Anything else moves every saved per-interface option for every user."""
    with_boards(monkeypatch, [("COM3", "esp32c6")])
    values = {value for value, _display in plugin.board_interfaces()}
    assert values == C6_RADIOS


def test_one_nrf_alone_gets_bare_names_too(monkeypatch):
    with_boards(monkeypatch, [("COM4", "nrf54l15")])
    values = {value for value, _display in plugin.board_interfaces()}
    assert values == NRF_RADIOS


def test_no_board_advertises_every_board_we_know(monkeypatch):
    """Wireshark asks what exists before anything is plugged in, and an
    interface that appears only once a board is attached cannot be selected in
    advance. With nothing attached we cannot know which board is coming, so we
    offer both."""
    with_boards(monkeypatch, [])
    values = {value for value, _display in plugin.board_interfaces()}
    assert values == C6_RADIOS | NRF_RADIOS


def test_two_boards_qualify_every_name_by_port(monkeypatch):
    with_boards(monkeypatch, [("COM3", "esp32c6"), ("COM4", "nrf54l15")])
    entries = plugin.board_interfaces()
    values = {value for value, _display in entries}
    assert values == {f"{radio}@COM3" for radio in C6_RADIOS} | {
        f"{radio}@COM4" for radio in NRF_RADIOS
    }
    assert len(entries) == 4


def test_a_radio_is_never_advertised_on_the_wrong_board(monkeypatch):
    """The regression that made this rule explicit: flattening (port, board)
    pairs back to bare ports advertised esp32c6-802154@COM4, on a port holding
    an nRF. It would have been selectable and failed on open."""
    with_boards(monkeypatch, [("COM3", "esp32c6"), ("COM4", "nrf54l15")])
    values = {value for value, _display in plugin.board_interfaces()}
    for radio in C6_RADIOS:
        assert f"{radio}@COM4" not in values
    assert "nrf54l15-802154@COM3" not in values


def test_a_board_only_gets_the_radios_its_firmware_has(monkeypatch):
    """Four interfaces, not six. There is no Wi-Fi radio on the nRF54L15 at
    all, and its BLE radio has no firmware behind it yet."""
    with_boards(monkeypatch, [("COM3", "esp32c6"), ("COM4", "nrf54l15")])
    values = {value for value, _display in plugin.board_interfaces()}
    assert "nrf54l15-wifi@COM4" not in values
    assert "nrf54l15-ble@COM4" not in values


def test_two_c6s_still_give_one_set_each(monkeypatch):
    """The original reason this naming exists: two boards capture two radios
    at once, which one shared front end forbids."""
    with_boards(monkeypatch, [("COM3", "esp32c6"), ("COM7", "esp32c6")])
    entries = plugin.board_interfaces()
    values = {value for value, _display in entries}
    assert values == {f"{radio}@{port}"
                      for radio in C6_RADIOS for port in ("COM3", "COM7")}
    assert len(entries) == 6


def test_boards_are_told_apart_in_the_display_name(monkeypatch):
    """Interfaces differing only by port would be unusable in Wireshark's list."""
    with_boards(monkeypatch, [("COM3", "esp32c6"), ("COM7", "esp32c6")])
    displays = [display for _value, display in plugin.board_interfaces()]
    assert len(set(displays)) == 6
    assert all("COM3" in d or "COM7" in d for d in displays)


def test_the_two_board_types_are_named_differently_in_the_display(monkeypatch):
    with_boards(monkeypatch, [("COM3", "esp32c6"), ("COM4", "nrf54l15")])
    displays = " ".join(d for _v, d in plugin.board_interfaces())
    assert "ESP32-C6" in displays
    assert "nRF54L15" in displays


def test_the_c6_display_names_are_unchanged(monkeypatch):
    """These strings are what a user sees in Wireshark's interface list, and
    generating them from board plus radio must reproduce them exactly."""
    with_boards(monkeypatch, [("COM3", "esp32c6")])
    displays = {value: display for value, display in plugin.board_interfaces()}
    assert displays["esp32c6-802154"] == "ESP32-C6 IEEE 802.15.4 (Zigbee/Thread)"
    assert displays["esp32c6-wifi"] == "ESP32-C6 Wi-Fi 2.4 GHz (802.11)"
    assert displays["esp32c6-ble"] == "ESP32-C6 Bluetooth LE (advertisements)"


@pytest.mark.parametrize("name,radio,port", [
    ("esp32c6-wifi", "esp32c6-wifi", None),
    ("esp32c6-wifi@COM7", "esp32c6-wifi", "COM7"),
    ("nrf54l15-802154@COM4", "nrf54l15-802154", "COM4"),
    ("esp32c6-802154@/dev/ttyACM1", "esp32c6-802154", "/dev/ttyACM1"),
])
def test_an_interface_name_splits_into_radio_and_board(name, radio, port):
    assert plugin.split_interface(name) == (radio, port)


def test_a_unix_device_path_survives_the_split():
    """A Linux port is /dev/ttyACM0, which contains no @ but does contain the
    separators one might have reached for first."""
    radio, port = plugin.split_interface("nrf54l15-802154@/dev/ttyACM0")
    assert (radio, port) == ("nrf54l15-802154", "/dev/ttyACM0")


def test_the_separator_is_not_a_character_a_port_can_contain():
    """If it were, splitting would cut a port name in half."""
    for port in ("COM3", "COM12", "/dev/ttyACM0", "/dev/ttyUSB1",
                 "/dev/cu.usbmodem14201"):
        assert plugin.PORT_SEPARATOR not in port
