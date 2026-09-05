import struct

import pytest

from esp32c6_sniffer.tap import (
    CHANNEL_MAX,
    CHANNEL_MIN,
    LINKTYPE_IEEE802_15_4_TAP,
    TAP_HEADER_LEN,
    FcsType,
    TapTlv,
    build_tap_record,
)

# Ack frame, sequence number 42, no FCS.
ACK_FRAME = bytes.fromhex("02002a")

# A record validated against tshark 4.6.8, which rendered it as
#   RSS: -42.50 dBm / Channel assignment: Page: Default (0), Number: 11
#   Link Quality Indicator: 120 / IEEE 802.15.4 Ack, Sequence Number: 42
# Byte-identical output is the strongest guarantee we can assert offline.
KNOWN_GOOD = bytes.fromhex(
    "0000" "1c00"
    "0100" "0400" "0000" "2ac2"
    "0300" "0300" "0b00" "0000"
    "0a00" "0100" "7800" "0000"
    "02002a"
)


def test_linktype_is_the_registered_value():
    assert LINKTYPE_IEEE802_15_4_TAP == 283


def test_matches_a_record_tshark_has_dissected():
    produced = build_tap_record(ACK_FRAME, channel=11, rssi_dbm=-42.5, lqi=120)
    assert produced.hex() == KNOWN_GOOD.hex()


def test_version_is_zero_and_reserved_is_zero():
    """Wireshark rejects any other version outright."""
    rec = build_tap_record(ACK_FRAME, channel=15, rssi_dbm=-40.0, lqi=200)
    assert rec[0] == 0
    assert rec[1] == 0


def test_length_covers_header_and_tlvs_but_not_payload():
    payload = b"\xaa" * 37
    rec = build_tap_record(payload, channel=11, rssi_dbm=-70.0, lqi=100)
    declared = struct.unpack_from("<H", rec, 2)[0]
    assert rec[declared:] == payload
    assert declared == len(rec) - len(payload)


def test_length_is_always_a_multiple_of_four():
    """Not cosmetic: an unaligned length yields [Malformed Packet]."""
    for lqi in range(0, 256, 37):
        rec = build_tap_record(b"\x00", channel=11, rssi_dbm=-1.0, lqi=lqi)
        assert struct.unpack_from("<H", rec, 2)[0] % 4 == 0


def test_every_tlv_is_four_byte_aligned_and_block_ends_exactly():
    rec = build_tap_record(b"\x00", channel=26, rssi_dbm=-15.5, lqi=255)
    declared = struct.unpack_from("<H", rec, 2)[0]
    off = TAP_HEADER_LEN
    seen = []
    while off < declared:
        tlv_type, length = struct.unpack_from("<HH", rec, off)
        seen.append(tlv_type)
        off += 4 + length + ((4 - length % 4) % 4)
    assert off == declared, "TLV block must end exactly at the declared length"
    assert seen == [TapTlv.RSS, TapTlv.CHANNEL_ASSIGNMENT, TapTlv.LQI]


def test_signal_strength_is_a_real_float_not_a_scaled_integer():
    rec = build_tap_record(b"\x00", channel=11, rssi_dbm=-42.5, lqi=1)
    value = struct.unpack_from("<f", rec, TAP_HEADER_LEN + 4)[0]
    assert value == pytest.approx(-42.5)


def test_channel_is_two_bytes_and_page_is_one():
    rec = build_tap_record(b"\x00", channel=26, rssi_dbm=-1.0, lqi=1, page=2)
    off = TAP_HEADER_LEN + 8  # past the RSS TLV
    tlv_type, length = struct.unpack_from("<HH", rec, off)
    assert tlv_type == TapTlv.CHANNEL_ASSIGNMENT
    assert length == 3
    channel, page = struct.unpack_from("<HB", rec, off + 4)
    assert channel == 26
    assert page == 2


def test_no_fcs_tlv_emitted_when_type_is_none():
    """Absence means NONE to Wireshark, so the default record stays minimal."""
    rec = build_tap_record(b"\x00", channel=11, rssi_dbm=-1.0, lqi=1)
    declared = struct.unpack_from("<H", rec, 2)[0]
    off = TAP_HEADER_LEN
    while off < declared:
        tlv_type, length = struct.unpack_from("<HH", rec, off)
        assert tlv_type != TapTlv.FCS_TYPE
        off += 4 + length + ((4 - length % 4) % 4)


def test_fcs_tlv_emitted_when_a_type_is_declared():
    rec = build_tap_record(
        b"\x00\x00", channel=11, rssi_dbm=-1.0, lqi=1, fcs_type=FcsType.CRC16
    )
    declared = struct.unpack_from("<H", rec, 2)[0]
    types = []
    off = TAP_HEADER_LEN
    while off < declared:
        tlv_type, length = struct.unpack_from("<HH", rec, off)
        types.append(tlv_type)
        off += 4 + length + ((4 - length % 4) % 4)
    assert TapTlv.FCS_TYPE in types


@pytest.mark.parametrize("channel", [CHANNEL_MIN, 15, CHANNEL_MAX])
def test_accepts_the_whole_valid_channel_range(channel):
    build_tap_record(b"\x00", channel=channel, rssi_dbm=-50.0, lqi=1)


@pytest.mark.parametrize("channel", [0, 10, 27, 99])
def test_rejects_channels_the_radio_cannot_tune(channel):
    with pytest.raises(ValueError):
        build_tap_record(b"\x00", channel=channel, rssi_dbm=-50.0, lqi=1)


@pytest.mark.parametrize("lqi", [-1, 256])
def test_rejects_out_of_range_lqi(lqi):
    with pytest.raises(ValueError):
        build_tap_record(b"\x00", channel=11, rssi_dbm=-50.0, lqi=lqi)
