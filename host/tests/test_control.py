import struct

import pytest

from esp32c6_sniffer.control import (
    COMMAND_PAYLOAD_LEN,
    REPLY_PAYLOAD_LEN,
    Antenna,
    Command,
    ControlError,
    decode_reply,
    encode_command,
)
from esp32c6_sniffer.framing import FrameType, decode_frame


def test_command_is_carried_in_a_control_cmd_frame():
    frame = decode_frame(encode_command(Command.SET_CHANNEL, 15))
    assert frame.ftype is FrameType.CONTROL_CMD


def test_command_payload_is_five_bytes():
    frame = decode_frame(encode_command(Command.SET_CHANNEL, 26))
    assert len(frame.payload) == COMMAND_PAYLOAD_LEN


def test_command_byte_then_little_endian_value():
    frame = decode_frame(encode_command(Command.SET_CHANNEL, 15))
    assert frame.payload[0] == int(Command.SET_CHANNEL)
    assert frame.payload[1:5] == (15).to_bytes(4, "little")


def test_value_round_trips_little_endian():
    frame = decode_frame(encode_command(Command.GET_INFO, 0x01020304))
    assert frame.payload[1:5] == bytes([0x04, 0x03, 0x02, 0x01])


@pytest.mark.parametrize("channel", [10, 27, 0, 999])
def test_channel_outside_the_radio_range_is_rejected(channel):
    """Fail here, not as a remote error after a round trip."""
    with pytest.raises(ValueError):
        encode_command(Command.SET_CHANNEL, channel)


@pytest.mark.parametrize("channel", [11, 15, 26])
def test_valid_channels_are_accepted(channel):
    encode_command(Command.SET_CHANNEL, channel)


@pytest.mark.parametrize("antenna", [Antenna.INTERNAL, Antenna.EXTERNAL])
def test_antenna_selection_accepts_both(antenna):
    encode_command(Command.SET_ANTENNA, int(antenna))


def test_antenna_rejects_anything_else():
    with pytest.raises(ValueError):
        encode_command(Command.SET_ANTENNA, 2)


def test_reply_decodes_success():
    payload = struct.pack("<BBI", int(Command.SET_CHANNEL), 0, 15)
    reply = decode_reply(payload)
    assert reply["command"] is Command.SET_CHANNEL
    assert reply["ok"] is True
    assert reply["status"] == 0
    assert reply["value"] == 15


def test_reply_decodes_failure_and_keeps_the_status_code():
    payload = struct.pack("<BBI", int(Command.SET_CHANNEL), 3, 0)
    reply = decode_reply(payload)
    assert reply["ok"] is False
    assert reply["status"] == 3


def test_reply_shorter_than_expected_is_rejected():
    with pytest.raises(ControlError):
        decode_reply(b"\x01\x00")


def test_reply_with_unknown_command_is_passed_through_not_rejected():
    """This used to raise, and raising was wrong.

    The board echoes back whatever command it was sent, so anything that puts
    an unknown identifier on the wire -- newer firmware, another tool sharing
    the port, a corrupted byte -- produced a reply that killed the capture loop
    reading it. Abusing the firmware with unknown commands crashed the host,
    not the board. Callers match against Command members, so a bare integer
    fails to match and the reply is ignored, which is the wanted behaviour.
    """
    reply = decode_reply(struct.pack("<BBI", 99, 0, 0))
    assert reply["command"] == 99
    assert reply["command"] not in tuple(Command)


def test_reply_shorter_than_the_payload_is_still_rejected():
    """A runt is a framing failure, which is a different thing entirely."""
    with pytest.raises(ControlError):
        decode_reply(b"\x01\x00")


def test_reply_length_constant_matches_the_struct():
    assert REPLY_PAYLOAD_LEN == struct.calcsize("<BBI")
