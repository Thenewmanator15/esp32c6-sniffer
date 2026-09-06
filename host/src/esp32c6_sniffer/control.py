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
from enum import IntEnum, IntFlag

from .framing import FrameType, encode_frame
from .tap import CHANNEL_MAX, CHANNEL_MIN

#: Largest snapshot length the firmware will accept, from
#: SN_80211_MAX_SNAPLEN in firmware/main/radio80211.h.
MAX_SNAPLEN = 512

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
    ENERGY_DETECT = 6
    SET_RADIO = 7
    WIFI_SCAN = 8
    SET_SNAPLEN = 9
    SET_FILTER = 10
    RADIO_POWER_CYCLE = 11
    SET_BANDWIDTH = 12
    SET_CTRL_FILTER = 13
    SET_CSI = 14
    RADIO_DIRTY = 15
    SET_BLE_SCAN = 16


class FrameFilter(IntFlag):
    """Which 802.11 frame types the board should deliver.

    Note this is a PASS mask despite being called a filter: a set bit means
    deliver that type, not block it. Values match WIFI_PROMIS_FILTER_MASK_* in
    esp_wifi_types_generic.h.

    Narrowing this is the cheapest defence against a busy channel. Control
    frames are the most numerous and the least informative -- acknowledgements
    mostly -- so dropping them costs little and buys a lot of link budget.
    """

    MGMT = 1 << 0
    CTRL = 1 << 1
    DATA = 1 << 2
    MISC = 1 << 3
    FCS_FAIL = 1 << 6

    #: Everything the radio will give us.
    ALL = MGMT | CTRL | DATA | MISC
    #: Beacons, probes and associations only. Enough to map a network.
    MGMT_ONLY = MGMT
    #: The usual choice for a busy channel: keep the meaning, drop the noise.
    NO_CTRL = MGMT | DATA


class Bandwidth(IntEnum):
    """Channel width, expressed as where the secondary channel sits.

    Watching a 40 MHz network on its primary channel alone sees half of it, so
    this has to match the network, not the preference.
    """

    HT20 = 0
    HT40_ABOVE = 1
    HT40_BELOW = 2


class CtrlFilter(IntFlag):
    """Which control-frame subtypes to deliver, a pass mask like FrameFilter.

    Acknowledgements dominate control-frame volume and carry almost nothing, so
    excluding them alone is often what keeps a busy channel within the link
    budget. Values match WIFI_PROMIS_CTRL_FILTER_MASK_* in
    esp_wifi_types_generic.h, which start at bit 23.
    """

    ADMINISTRATIVE = 1 << 23   # wrapper, block-ack request and block-ack
    BAR = 1 << 24
    BA = 1 << 25
    PSPOLL = 1 << 26
    RTS = 1 << 27
    CTS = 1 << 28
    ACK = 1 << 29
    CFEND = 1 << 30
    CFENDACK = 1 << 31

    ALL = (ADMINISTRATIVE | BAR | BA | PSPOLL | RTS | CTS | ACK | CFEND
           | CFENDACK)
    #: Keep the frames that describe the conversation, drop the acknowledgement
    #: storm.
    NO_ACK = ALL & ~ACK


class Radio(IntEnum):
    """Which radio the capture build should use.

    One at a time, always. The C6 has a single 2.4 GHz front end shared by all
    three radios, and Espressif's coexistence matrix lists the combinations we
    would want as unsupported or unstable.
    """

    IEEE802154 = 0
    WIFI = 1
    #: Observer only: advertisements and scan responses, never connections.
    #: A connected device goes quiet the moment it stops advertising.
    BLE = 2


class Antenna(IntEnum):
    INTERNAL = 0
    EXTERNAL = 1


class ControlError(Exception):
    """Raised for a malformed command or reply."""


# The two radios have different channel numbering, and they overlap
# confusingly: 802.15.4 channel 11 and Wi-Fi channel 11 are different
# frequencies entirely. Validating against the wrong one silently accepts a
# number that will fail on the board, so the caller says which radio it means.
WIFI_CHANNEL_MIN = 1
WIFI_CHANNEL_MAX = 14

_CHANNEL_RANGE = {
    Radio.IEEE802154: (CHANNEL_MIN, CHANNEL_MAX),
    Radio.WIFI: (WIFI_CHANNEL_MIN, WIFI_CHANNEL_MAX),
}


def encode_command(
    command: Command,
    value: int = 0,
    radio: Radio = Radio.IEEE802154,
) -> bytes:
    """Build a complete framed command ready to write to the serial port.

    Range checking happens here rather than only on the board, so a bad channel
    fails immediately and visibly instead of arriving as a remote error. It
    needs `radio` because the two use different channel numbering.
    """
    if command is Command.SET_CHANNEL:
        if radio not in _CHANNEL_RANGE:
            # BLE has no channel to select: the controller rotates the three
            # advertising channels itself. A KeyError here would be a confusing
            # way to learn that.
            raise ValueError(f"{radio.name} has no selectable channel")
        low, high = _CHANNEL_RANGE[radio]
        if not low <= value <= high:
            raise ValueError(
                f"channel {value} outside the {radio.name} range {low}-{high}"
            )
    if command is Command.SET_ANTENNA and value not in tuple(Antenna):
        raise ValueError(f"antenna {value} is not 0 (internal) or 1 (external)")
    if command is Command.SET_SNAPLEN and not 1 <= value <= MAX_SNAPLEN:
        raise ValueError(f"snaplen {value} outside 1-{MAX_SNAPLEN}")
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"value {value} does not fit in 32 bits")

    payload = _COMMAND.pack(int(command), value)
    # The sequence number is irrelevant on this path; the board does not track
    # inbound ordering and replies echo the command instead.
    return encode_frame(FrameType.CONTROL_CMD, 0, payload)


def decode_reply(payload: bytes) -> dict:
    """Decode a CONTROL_REPLY frame's payload.

    An unrecognised command identifier comes back as a plain integer rather
    than raising. Raising was wrong twice over: the board echoes back whatever
    it was sent, so anything that puts an unknown command on the wire -- newer
    firmware, another tool sharing the port, a corrupted byte -- produced a
    reply that killed the capture loop reading it. And callers compare against
    `Command` members, so an integer simply fails to match and the reply is
    ignored, which is the wanted behaviour anyway.

    A payload too short to be a reply at all still raises: that is a framing
    failure, not an unknown message.
    """
    if len(payload) < REPLY_PAYLOAD_LEN:
        raise ControlError(
            f"reply is {len(payload)} bytes, expected {REPLY_PAYLOAD_LEN}"
        )
    command, status, value = _REPLY.unpack(payload[:REPLY_PAYLOAD_LEN])
    try:
        command_field: Command | int = Command(command)
    except ValueError:
        command_field = command
    return {"command": command_field, "ok": status == 0, "status": status,
            "value": value}
