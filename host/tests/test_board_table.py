"""Which board is on which port, decided by USB id before anything is opened.

The extcap must name its interfaces before a port is ever opened -- Wireshark
asks what exists while nothing is plugged in -- so identity cannot come from a
control command. It has to come from enumeration, which already has it and was
throwing it away.
"""

import importlib.util
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_boards", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


class FakePort:
    """What pyserial's list_ports.comports() returns, reduced to what we read."""

    def __init__(self, device, vid, pid):
        self.device = device
        self.vid = vid
        self.pid = pid


def with_comports(monkeypatch, ports):
    monkeypatch.setattr(plugin, "list_comports", lambda: list(ports))


def test_the_c6_is_recognised_by_its_usb_id():
    assert plugin.BOARDS[(0x303A, 0x1001)]["id"] == "esp32c6"


def test_the_nrf_is_recognised_by_its_usb_id():
    assert plugin.BOARDS[(0x2886, 0x0066)]["id"] == "nrf54l15"


def test_the_nrf_has_no_wifi_radio():
    """The silicon has none. Offering one would be a promise nothing can keep."""
    assert "wifi" not in plugin.BOARDS[(0x2886, 0x0066)]["radios"]


def test_a_boards_radios_are_what_its_firmware_implements():
    """Not what the silicon can do. The nRF54L15 has a BLE radio; it gets a BLE
    interface when there is firmware behind it and not before, because an
    interface that cannot capture is worse than an absent one -- it is
    selectable, and it fails after the operator has committed to a capture."""
    assert plugin.BOARDS[(0x2886, 0x0066)]["radios"] == ("802154",)


def test_both_boards_declare_an_antenna_switch():
    """The C6 carries an FM8625H on GPIO3/GPIO14. The spike found the XIAO
    nRF54L15 has the same arrangement -- rfsw_pwr on gpio2.3 powering the
    switch, rfsw_ctl on gpio2.5 selecting the antenna -- which the design had
    originally denied. See https://github.com/Thenewmanator15/nrf54l15-sniffer/blob/main/docs/2026-09-14-nrf54l15-spike.md."""
    assert plugin.BOARDS[(0x303A, 0x1001)]["antenna"] is True
    assert plugin.BOARDS[(0x2886, 0x0066)]["antenna"] is True


def test_discovery_reports_the_board_beside_the_port(monkeypatch):
    with_comports(monkeypatch, [
        FakePort("COM3", 0x303A, 0x1001),
        FakePort("COM4", 0x2886, 0x0066),
    ])
    assert plugin.find_board_ports() == [("COM3", "esp32c6"), ("COM4", "nrf54l15")]


def test_an_unknown_usb_id_is_skipped_not_guessed_at(monkeypatch):
    """A board with the wrong capabilities is worse than a board that is
    absent: it is selectable, and every option in its dialog is a lie."""
    with_comports(monkeypatch, [
        FakePort("COM9", 0x1234, 0x5678),
        FakePort("COM3", 0x303A, 0x1001),
    ])
    assert plugin.find_board_ports() == [("COM3", "esp32c6")]


def test_a_port_with_no_usb_id_is_skipped(monkeypatch):
    """Bluetooth and motherboard serial ports enumerate with vid and pid None,
    and None must not match a board by accident."""
    with_comports(monkeypatch, [FakePort("COM1", None, None)])
    assert plugin.find_board_ports() == []


def test_enumeration_failing_is_not_fatal(monkeypatch):
    """This must never be the reason a capture fails."""
    def explode():
        raise OSError("no serial subsystem")

    monkeypatch.setattr(plugin, "list_comports", explode)
    try:
        result = plugin.find_board_ports()
    except OSError:
        raise AssertionError("find_board_ports must swallow enumeration errors")
    assert result == []


def test_the_default_port_is_the_first_board_found(monkeypatch):
    """default_port() reads a port out of the pairs, and would otherwise put a
    whole tuple into the dialog's text field."""
    with_comports(monkeypatch, [FakePort("COM7", 0x303A, 0x1001)])
    assert plugin.default_port() == "COM7"


def test_the_default_port_falls_back_when_nothing_is_attached(monkeypatch):
    """The dialog must show something sensible rather than an empty required
    field, for anyone configuring an interface before plugging the board in."""
    with_comports(monkeypatch, [])
    assert plugin.default_port() == plugin.DEFAULT_PORT
