"""Bluetooth Low Energy records, carried as HCI.

The board runs its Bluetooth controller with no host stack and drives it over
HCI directly, so what arrives here is the controller's own HCI events, byte for
byte. That matters: Wireshark dissects them with its own HCI dissector, so
advertising reports come out with their address types, RSSI and the whole AD
structure chain already understood. Nothing about the BLE payload is
interpreted here, which is the point -- there is no bespoke format to get
wrong.

The link type is BLUETOOTH_HCI_H4_WITH_PHDR (201) rather than plain H4 (187).
The pseudo-header is a four-byte big-endian direction flag, and it is worth the
four bytes: plain H4 leaves Wireshark guessing whether a packet went to or from
the controller, and a capture that cannot say which way a packet went is
harder to read than one that can.

Wire layout of the frame payload, little-endian, matching sn_ble_meta_t in
firmware/main/radio_ble.h::

    uint64 timestamp_us
    uint16 orig_len
    uint8  flags
    uint8  reserved
    ...    the HCI packet, starting with its H4 packet-type byte
"""

from __future__ import annotations

import struct

_META = struct.Struct("<QHBB")
META_LEN = _META.size  # 12

LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR = 201

FLAG_TRUNCATED = 0x01

#: Direction, as the pseudo-header wants it: big-endian, 1 for controller to
#: host. Everything forwarded is received, because the board deliberately does
#: not put its own scan-setup commands into the capture.
_DIRECTION_RECEIVED = struct.pack(">I", 1)

#: H4 packet types, for the caller that wants to count events without a full
#: HCI dissector.
H4_COMMAND = 0x01
H4_ACL = 0x02
H4_EVENT = 0x04

EVENT_LE_META = 0x3E
LE_SUBEVENT_ADV_REPORT = 0x02
LE_SUBEVENT_EXT_ADV_REPORT = 0x0D


def build_ble_record(payload: bytes):
    """Turns one BLE frame payload into (pcap record, hci_len, timestamp_us).

    Raises ValueError if the payload cannot hold its own metadata, so the
    caller counts it as malformed rather than emitting a short record.
    """
    if len(payload) <= META_LEN:
        raise ValueError(
            f"BLE payload is {len(payload)} bytes, needs more than {META_LEN}"
        )
    timestamp_us, _orig_len, _flags, _reserved = _META.unpack_from(payload)
    hci = payload[META_LEN:]
    return _DIRECTION_RECEIVED + hci, len(hci), timestamp_us


def is_advertising_report(payload: bytes) -> bool:
    """True if this frame carries an LE advertising report.

    Used for counting only. The dissection that matters happens in Wireshark;
    this exists so a survey can say how many advertisements it saw without
    pulling in an HCI parser.
    """
    if len(payload) <= META_LEN:
        return False
    hci = payload[META_LEN:]
    return (len(hci) >= 4 and hci[0] == H4_EVENT and hci[1] == EVENT_LE_META
            and hci[3] in (LE_SUBEVENT_ADV_REPORT, LE_SUBEVENT_EXT_ADV_REPORT))


def advertiser_address(payload: bytes) -> str | None:
    """The advertiser's address from a legacy advertising report, or None.

    Legacy layout after the H4 type byte: event code, parameter length,
    subevent, number of reports, then per report the event type, address type
    and six address bytes. Only the single-report case is decoded, which is
    what the controller emits here; anything else returns None rather than
    guessing at an offset.
    """
    if not is_advertising_report(payload):
        return None
    hci = payload[META_LEN:]
    if hci[3] != LE_SUBEVENT_ADV_REPORT or len(hci) < 13:
        return None
    if hci[4] != 1:                 # number of reports
        return None
    address = hci[7:13]
    # HCI carries addresses least significant byte first; they are written the
    # other way round.
    return ":".join(f"{b:02x}" for b in reversed(address))
