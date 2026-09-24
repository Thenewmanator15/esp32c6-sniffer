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


def test_packets_keep_their_bytes_for_naming_the_network():
    meta = struct.pack("<BBbBQ", 15, 200, -60, 0, 123456)
    assert survey.packet_entries(frame(FrameType.PACKET, meta + b"\x41\x88\x07")) == [(-60, b"\x41\x88\x07")]
    entries = [BatchEntry(1000, 200, -55, b"\x41\x88\x01")]
    batch = frame(FrameType.PACKET_BATCH, encode_packet_batch(25, entries))
    assert survey.packet_entries(batch) == [(-55, b"\x41\x88\x01")]


# A secured Thread data frame and a Data Request, both on PAN 0x1234, from two
# short addresses; a Zigbee NWK data frame on PAN 0xbeef; an acknowledgement.
AUX = bytes([0x0D]) + (7).to_bytes(4, "little") + b"\x01"
THREAD_DATA = (0x9869).to_bytes(2, "little") + b"\x01" + b"\x34\x12" + b"\x00\x04" + b"\x0c\xac" + AUX + b"\xaa"
THREAD_POLL = (0x986B).to_bytes(2, "little") + b"\x02" + b"\x34\x12" + b"\x00\x04" + b"\x0d\xac" + AUX + b"\x04"
ZIGBEE_DATA = (0x8841).to_bytes(2, "little") + b"\x03" + b"\xef\xbe" + b"\xff\xff" + b"\x00\x00" + b"\x08\x02\xfc\xff"
ACK = (0x0002).to_bytes(2, "little") + b"\x01"


def test_networks_are_named_counted_and_their_sleepy_devices_found():
    rows = survey.networks({
        15: [(-60, THREAD_DATA), (-62, THREAD_POLL), (-61, THREAD_POLL), (-40, ACK)],
        20: [(-80, ZIGBEE_DATA)],
    })
    assert [(r.channel, r.pan, r.network, r.frames, r.addresses, r.sleepy, r.rssi)
            for r in rows] == [
        (15, 0x1234, "Thread", 3, 2, 1, -61),
        (20, 0xBEEF, "Zigbee", 1, 1, 0, -80),
    ]


def test_frames_that_name_no_stack_leave_the_network_unknown():
    unsecured_command = (0x8863).to_bytes(2, "little") + b"\x04" + b"\x99\x99" + b"\x00\x00" + b"\x01\x00" + b"\x07"
    rows = survey.networks({11: [(-70, unsecured_command)]})
    assert [(r.pan, r.network) for r in rows] == [(0x9999, "unknown")]


def test_unreadable_frames_are_skipped_not_fatal():
    assert survey.networks({26: [(-50, b"\x41"), (-50, b"")]}) == []


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
