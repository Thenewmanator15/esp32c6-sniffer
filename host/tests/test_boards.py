"""Which board is on a port, and a raw command link that talks to it properly.

The board table lived in the extcap script, where nothing else could reach it,
so every tool that opened a port did it the ESP32-C6's way: 115200 baud, no
handshake. The C6 does not care -- its port is USB CDC, with no line rate --
but the nRF54L15 is reached through a UART bridge at 1 Mbaud, and its bridge
hands over stale bytes in front of the first reply. survey.py and spectrum.py
could not drive it at all.
"""

import importlib.util
import pathlib
from types import SimpleNamespace

import pytest

from esp32c6_sniffer import boards
from esp32c6_sniffer.control import Command
from test_open_handshake import STALE, BridgedPort

PLUGIN = pathlib.Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def _plugin():
    spec = importlib.util.spec_from_file_location("extcap_plugin_boards", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def port(device, vid, pid):
    return SimpleNamespace(device=device, vid=vid, pid=pid)


C6 = port("COM3", 0x303A, 0x1001)
NRF = port("COM4", 0x2886, 0x0066)
OTHER = port("COM9", 0x1234, 0x5678)


def test_the_plugin_uses_the_one_table():
    assert _plugin().BOARDS is not None
    assert _plugin().BOARDS == boards.BOARDS


def test_a_port_is_named_by_its_usb_id():
    assert boards.board_on_port("COM4", comports=[C6, NRF])["id"] == "nrf54l15"
    assert boards.board_on_port("COM3", comports=[C6, NRF])["id"] == "esp32c6"


def test_an_unrecognised_port_is_not_guessed_at():
    assert boards.board_on_port("COM9", comports=[OTHER]) is None
    assert boards.board_on_port("COM7", comports=[C6]) is None


def test_the_bridged_board_is_the_nrf():
    assert boards.board_by_id("nrf54l15")["bridged"] is True
    assert boards.board_by_id("esp32c6")["bridged"] is False


class Opened:
    """Records how a port was opened, and hands back a fake."""

    def __init__(self, fake):
        self.fake, self.baud = fake, None

    def __call__(self, device, baud, **_):
        self.baud = baud
        return self.fake


def test_a_link_opens_at_its_boards_rate():
    opened = Opened(BridgedPort(version=3))
    boards.BoardLink("COM4", comports=[NRF], serial_factory=opened).open()
    assert opened.baud == 1_000_000


def test_an_unrecognised_port_opens_as_a_c6_did_before():
    """The tools opened every port at 115200 before this existed, and a C6 whose
    USB id the OS does not report must go on working."""
    opened = Opened(BridgedPort(version=6))
    link = boards.BoardLink("COM9", comports=[OTHER], serial_factory=opened).open()
    assert opened.baud == 115200
    assert link.board["id"] == "esp32c6"


def test_the_first_reply_through_the_bridge_is_asked_for_again():
    """The measured case: a stale, truncated frame swallows the first reply."""
    fake = BridgedPort(version=3, stale=STALE)
    link = boards.BoardLink("COM4", comports=[NRF], serial_factory=Opened(fake)).open()
    assert link.firmware_version == 3
    assert fake.commands.count(Command.GET_INFO) == 2


def test_a_link_carries_commands_once_open():
    fake = BridgedPort(version=3)
    link = boards.BoardLink("COM4", comports=[NRF], serial_factory=Opened(fake)).open()
    reply = link.command(Command.SET_CHANNEL, 15)
    assert reply["command"] is Command.SET_CHANNEL and reply["ok"]


def test_a_board_that_never_answers_times_out():
    class Silent(BridgedPort):
        def write(self, data):
            return len(data)

    with pytest.raises(TimeoutError):
        boards.BoardLink("COM3", comports=[C6], serial_factory=Opened(Silent(6)),
                         timeout=0.2).open()
