"""The survey tools, now that they can drive either board.

survey.py counted traffic from PACKET frames only. The nRF54L15 sends most of
what it captures in PACKET_BATCH frames, to fit its UART link, so every
channel would have surveyed as quiet on that board however busy it was.
"""

import pathlib
import struct
import sys

sys.path.append(str(pathlib.Path(__file__).resolve().parents[1] / "tools"))

import spectrum  # noqa: E402
import survey  # noqa: E402
from esp32c6_sniffer.batch import BatchEntry, encode_packet_batch  # noqa: E402
from esp32c6_sniffer.boards import BoardLink  # noqa: E402
from esp32c6_sniffer.framing import FrameType, encode_frame  # noqa: E402
from esp32c6_sniffer.parser import StreamParser  # noqa: E402


def frame(ftype, payload):
    return StreamParser().feed(encode_frame(ftype, 1, payload))[0]


def test_a_single_packet_gives_its_signal():
    meta = struct.pack("<BBbBQ", 15, 200, -60, 0, 123456)
    assert survey.packet_rssis(frame(FrameType.PACKET, meta + b"\x41\x88")) == [-60]


def test_a_batch_gives_the_signal_of_every_packet_in_it():
    entries = [BatchEntry(1000, 200, -55, b"\x41\x88\x01"),
               BatchEntry(2000, 180, -70, b"\x41\x88\x02")]
    batch = frame(FrameType.PACKET_BATCH, encode_packet_batch(25, entries))
    assert survey.packet_rssis(batch) == [-55, -70]


def test_anything_else_gives_nothing():
    assert survey.packet_rssis(frame(FrameType.LOG, b"hello")) == []
    assert survey.packet_rssis(frame(FrameType.PACKET_BATCH, b"\x19")) == []


import ble_survey  # noqa: E402
import wifi_survey  # noqa: E402
from esp32c6_sniffer import boards  # noqa: E402
import pytest  # noqa: E402

NRF = boards.board_by_id("nrf54l15")


def test_the_wifi_survey_refuses_a_board_with_no_wifi(monkeypatch, capsys):
    """Its first act is to power-cycle the C6's radio domain, which means
    nothing to the nRF54L15 and would fail as a timeout rather than a reason."""
    monkeypatch.setattr(boards, "board_on_port", lambda port, comports=None: NRF)
    monkeypatch.setattr(wifi_survey, "ensure_wifi_ready",
                        lambda port: pytest.fail("touched the board"))
    monkeypatch.setattr(sys, "argv", ["wifi_survey.py", "--port", "COM4"])
    assert wifi_survey.main() != 0
    assert "no Wi-Fi radio" in capsys.readouterr().err


def test_the_ble_survey_opens_its_session_as_the_board_on_the_port(monkeypatch):
    opened = {}

    class Stop(Exception):
        pass

    def fake_session(port, **kwargs):
        opened.update(kwargs, port=port)
        raise Stop

    monkeypatch.setattr(boards, "board_on_port", lambda port, comports=None: NRF)
    monkeypatch.setattr(ble_survey, "CaptureSession", fake_session)
    monkeypatch.setattr(sys, "argv", ["ble_survey.py", "--port", "COM4"])
    with pytest.raises(Stop):
        ble_survey.main()
    assert opened["board"] == "nrf54l15" and opened["baud"] == 1_000_000


def test_both_tools_open_the_board_through_a_board_link():
    """Rather than at the C6's 115200 with no handshake, which is what left
    the nRF54L15 unreachable from them."""
    assert survey.BoardLink is BoardLink
    assert spectrum.BoardLink is BoardLink
    assert not hasattr(survey, "_open") and not hasattr(spectrum, "_open")
