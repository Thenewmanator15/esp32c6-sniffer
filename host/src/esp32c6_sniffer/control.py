"""Control channel, host to board.

Milestone 1's link only transmitted. The Wireshark plugin needs to select a
radio channel and an antenna per capture session, so this adds the inbound
direction using the same framing.

Command payload, 5 bytes::

    command  1  Command enum
    value    4  little-endian, meaning depends on the command

Reply payload, 6 bytes, carried in a CONTROL_REPLY frame::

    command  1  echoed, so a reply can be matched to its request
    status   1  0 = ok, non-zero = failure
    value    4  little-endian, meaning depends on the command

Commands are echoed back rather than correlated by sequence number, because the
board assigns sequence numbers itself and the host does not know them in
advance.
"""

from __future__ import annotations

import struct
from enum import IntEnum

from .framing import FrameType, encode_frame
from .tap import CHANNEL_MAX, CHANNEL_MIN

COMMAND_PAYLOAD_LEN = 5
REPLY_PAYLOAD_LEN = 6

_COMMAND = struct.Struct("<BI")
_REPLY = struct.Struct("<BBI")


class Command(IntEnum):
    SET_CHANNEL = 1
    SET_ANTENNA = 2
    START = 3
    STOP = 4
    GET_INFO = 5


class Antenna(IntEnum):
    INTERNAL = 0
    EXTERNAL = 1


class ControlError(Exception):
    """Raised for a malformed command or reply."""


def encode_command(command: Command, value: int = 0) -> bytes:
    """Build a complete framed command ready to write to the serial port.

    Range checking happens here rather than only on the board, so a bad channel
    fails immediately and visibly instead of arriving as a remote error.
    """
    if command is Command.SET_CHANNEL and not (
        CHANNEL_MIN <= value <= CHANNEL_MAX
    ):
        raise ValueError(
            f"channel {value} outside the radio's range "
            f"{CHANNEL_MIN}-{CHANNEL_MAX}"
        )
    if command is Command.SET_ANTENNA and value not in tuple(Antenna):
        raise ValueError(f"antenna {value} is not 0 (internal) or 1 (external)")
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"value {value} does not fit in 32 bits")

    payload = _COMMAND.pack(int(command), value)
    # The sequence number is irrelevant on this path; the board does not track
    # inbound ordering and replies echo the command instead.
    return encode_frame(FrameType.CONTROL_CMD, 0, payload)


def decode_reply(payload: bytes) -> dict:
    """Decode a CONTROL_REPLY frame's payload."""
    if len(payload) < REPLY_PAYLOAD_LEN:
        raise ControlError(
            f"reply is {len(payload)} bytes, expected {REPLY_PAYLOAD_LEN}"
        )
    command, status, value = _REPLY.unpack(payload[:REPLY_PAYLOAD_LEN])
    try:
        command_enum = Command(command)
    except ValueError as exc:
        raise ControlError(f"unknown command {command} in reply") from exc
    return {"command": command_enum, "ok": status == 0, "status": status,
            "value": value}
