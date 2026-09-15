"""A dialog must not offer a control the board cannot honour.

An option that does nothing is worse than an absent one: it looks like a
setting, the operator sets it, and the only way they learn it was never
connected to anything is by the capture behaving as though they had not.
"""

import importlib.util
from pathlib import Path

import pytest

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_caps", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


@pytest.fixture
def no_boards(monkeypatch):
    """Nothing attached, so the output depends on the board table and not on
    whatever happens to be plugged into the machine running the tests."""
    monkeypatch.setattr(plugin, "find_board_ports", lambda: [])


def config_for(interface, capsys):
    plugin.print_config(interface)
    return capsys.readouterr().out


def test_an_interface_maps_back_to_its_board():
    assert plugin.board_for_interface("nrf54l15-802154")["id"] == "nrf54l15"
    assert plugin.board_for_interface("esp32c6-wifi")["id"] == "esp32c6"


def test_a_qualified_interface_maps_back_too():
    """print_config is handed whatever Wireshark names, which carries the port
    once more than one board is attached."""
    assert plugin.board_for_interface("nrf54l15-802154@COM4")["id"] == "nrf54l15"
    assert plugin.board_for_interface("esp32c6-ble@/dev/ttyACM0")["id"] == "esp32c6"


def test_the_c6_still_offers_an_antenna(no_boards, capsys):
    assert "--antenna" in config_for("esp32c6-802154", capsys)


def test_the_nrf_offers_an_antenna_too(no_boards, capsys):
    """The spike found this board has the same arrangement as the C6: a
    powered RF switch selecting between an onboard ceramic antenna and an
    external IPEX connector. The design originally claimed it had neither.
    See docs/2026-09-14-nrf54l15-spike.md."""
    assert "--antenna" in config_for("nrf54l15-802154", capsys)


def test_a_board_without_a_switch_is_offered_none(no_boards, capsys, monkeypatch):
    """The gating itself must be tested, even though both boards we currently
    know happen to have a switch. Without this the capability is asserted
    nowhere and would rot the first time a board without one is added."""
    key = (0x2886, 0x0066)
    fake = dict(plugin.BOARDS[key])
    fake["antenna"] = False
    monkeypatch.setitem(plugin.BOARDS, key, fake)
    assert "--antenna" not in config_for("nrf54l15-802154", capsys)


def test_the_port_tooltip_names_the_right_usb_id(no_boards, capsys):
    """The tooltip told every board it was detected by 303A:1001, which is the
    C6's id and a lie on anything else."""
    assert "2886:0066" in config_for("nrf54l15-802154", capsys)
    assert "303A:1001" in config_for("esp32c6-802154", capsys)


def test_the_nrf_still_offers_a_channel(no_boards, capsys):
    """Gating must remove only what the board lacks."""
    assert "--channel" in config_for("nrf54l15-802154", capsys)


def test_a_qualified_interface_still_produces_a_config(no_boards, capsys):
    """print_config used to index INTERFACES with the name it was given, which
    raises KeyError on the qualified form that two attached boards produce."""
    out = config_for("nrf54l15-802154@COM4", capsys)
    assert "--channel" in out


def test_the_detected_note_lists_only_this_boards_ports(monkeypatch, capsys):
    """Offering the nRF's port as a place to find a C6 would be a confident
    wrong answer in a required field."""
    monkeypatch.setattr(plugin, "find_board_ports",
                        lambda: [("COM3", "esp32c6"), ("COM4", "nrf54l15")])
    c6 = config_for("esp32c6-802154", capsys)
    assert "COM3" in c6 and "COM4" not in c6
    nrf = config_for("nrf54l15-802154", capsys)
    assert "COM4" in nrf and "COM3" not in nrf


def test_the_antenna_tooltip_does_not_borrow_another_boards_measurement(
        no_boards, capsys):
    """+13 to +14 dB was measured on the C6, against its switch and its two
    antennas. Repeating it on a board where nobody has measured anything would
    be presenting a guess as a measurement, which is the one thing this
    project's documentation is careful never to do."""
    c6 = config_for("esp32c6-802154", capsys)
    nrf = config_for("nrf54l15-802154", capsys)
    assert "+13 to +14 dB" in c6
    assert "+13 to +14 dB" not in nrf
    assert "not been measured" in nrf


def test_each_board_names_its_own_hardware_for_the_capture_file():
    """The pcapng section header carries the hardware string, and a capture
    that describes itself must describe the right board. This was hardcoded to
    the C6, so an nRF capture claimed to have come from an ESP32-C6 -- wrong
    in the one field a reader would trust to tell them otherwise."""
    assert "ESP32-C6" in plugin.BOARDS[(0x303A, 0x1001)]["hardware"]
    assert "nRF54L15" in plugin.BOARDS[(0x2886, 0x0066)]["hardware"]
    assert "ESP32-C6" not in plugin.BOARDS[(0x2886, 0x0066)]["hardware"]
