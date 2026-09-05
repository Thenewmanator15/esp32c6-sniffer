"""IEEE 802.15.4 TAP records, link type 283.

Wireshark 3.0 and later dissect this natively, so no custom dissector is needed.
The metadata travels in type-length-value blocks ahead of the raw frame.

Specification: "IEEE 802.15.4 TAP Link Type Specification" v1.3, James Ko,
Exegin Technologies. The repository holds a LaTeX source and a PDF, no README:
https://gitlab.com/exegin/ieee802-15-4-tap/-/raw/master/ieee802154_tap.tex

Every constant below was cross-checked against Wireshark's own dissector at the
v4.6.8 tag (epan/dissectors/packet-ieee802154.c) and validated by generating
records and confirming tshark 4.6.8 dissects them. The link type mapping is in
wiretap/pcap-common.c: { 283, WTAP_ENCAP_IEEE802_15_4_TAP }.

Layout::

    header   version (1) | reserved (1) | length (2)     all little-endian
    TLV      type (2)    | length (2)   | value | zero padding to 4 bytes
    payload  raw 802.15.4 MPDU, starting at `length` bytes in

Four rules that produce silently wrong or malformed output if broken:

* `length` covers the header and TLVs ONLY, never the payload, and must be a
  multiple of 4. Wireshark computes padding from the TLV length and then reads
  it, so an unaligned total runs off the end of the TLV block and yields
  "[Malformed Packet]".
* A TLV's own length field EXCLUDES its padding, while the header length
  INCLUDES it.
* Version must be 0. Wireshark rejects anything else outright, leaving the
  frame undissected.
* FCS handling is governed entirely by the FCS Type TLV, and its absence means
  NONE. Declaring a type but omitting the bytes gives a malformed packet;
  including bytes without declaring a type mis-parses them into the frame.
  Values of 3 or more make Wireshark abandon the payload with no obvious error.
"""

from __future__ import annotations

import struct
from enum import IntEnum

LINKTYPE_IEEE802_15_4_TAP = 283

TAP_VERSION = 0
TAP_HEADER_LEN = 4

# The 2.4 GHz O-QPSK channel range, which is all the ESP32-C6 radio supports.
CHANNEL_MIN = 11
CHANNEL_MAX = 26

_HEADER = struct.Struct("<BBH")
_TLV_HEADER = struct.Struct("<HH")


class TapTlv(IntEnum):
    """TLV identifiers, from the specification and Wireshark's enum."""

    FCS_TYPE = 0
    RSS = 1
    BIT_RATE = 2
    CHANNEL_ASSIGNMENT = 3
    SUN_PHY_INFO = 4
    START_OF_FRAME_TS = 5
    END_OF_FRAME_TS = 6
    ASN = 7
    SLOT_START_TS = 8
    TIMESLOT_LENGTH = 9
    LQI = 10
    CHANNEL_FREQUENCY = 11
    CHANNEL_PLAN = 12
    PHY_HEADER = 13


class FcsType(IntEnum):
    NONE = 0
    CRC16 = 1
    CRC32 = 2


def _tlv(tlv_type: TapTlv, value: bytes) -> bytes:
    """One TLV, zero-padded to a 4-byte boundary.

    The length field carries the unpadded length; the padding is still emitted
    and still counts toward the header's total.
    """
    padding = (4 - len(value) % 4) % 4
    return _TLV_HEADER.pack(int(tlv_type), len(value)) + value + b"\x00" * padding


def build_tap_record(
    frame: bytes,
    *,
    channel: int,
    rssi_dbm: float,
    lqi: int,
    fcs_type: FcsType = FcsType.NONE,
    page: int = 0,
) -> bytes:
    """Wrap one 802.15.4 frame with its radio metadata.

    `frame` is the raw MPDU. Include the frame check sequence bytes only when
    `fcs_type` says they are there, and exclude them when it says NONE.
    """
    if not CHANNEL_MIN <= channel <= CHANNEL_MAX:
        raise ValueError(
            f"channel {channel} outside the 2.4 GHz range "
            f"{CHANNEL_MIN}-{CHANNEL_MAX}"
        )
    if not 0 <= lqi <= 255:
        raise ValueError(f"LQI {lqi} outside 0-255")
    if not 0 <= page <= 255:
        raise ValueError(f"channel page {page} outside 0-255")

    tlvs = b"".join(
        (
            _tlv(TapTlv.RSS, struct.pack("<f", rssi_dbm)),
            _tlv(TapTlv.CHANNEL_ASSIGNMENT, struct.pack("<HB", channel, page)),
            _tlv(TapTlv.LQI, struct.pack("<B", lqi)),
        )
    )
    # Only declare an FCS type when it is not the NONE default, matching what
    # Nordic's shipping sniffer emits and keeping records minimal.
    if fcs_type is not FcsType.NONE:
        tlvs += _tlv(TapTlv.FCS_TYPE, struct.pack("<B", int(fcs_type)))

    length = TAP_HEADER_LEN + len(tlvs)
    assert length % 4 == 0, "TAP length must be a multiple of 4"
    return _HEADER.pack(TAP_VERSION, 0, length) + tlvs + frame
