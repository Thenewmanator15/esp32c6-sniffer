"""Decoding of channel state information records."""

import struct

import pytest

from esp32c6_sniffer.csi import (
    CSV_HEADER,
    FLAG_FIRST_WORD_INVALID,
    HEADER_LEN,
    parse_csi_record,
    to_csv_row,
)

HEADER = struct.Struct("<QbbBB6sHBH")


def record(csi: bytes, *, timestamp=1234567, rssi=-60, noise=-95, channel=6,
           phy=1, mac=b"\xaa\xbb\xcc\xdd\xee\xff", seq=42, flags=0,
           declared=None) -> bytes:
    length = len(csi) if declared is None else declared
    return HEADER.pack(timestamp, rssi, noise, channel, phy, mac, seq, flags,
                       length) + csi


def test_header_length_matches_the_firmware_constant():
    """A one-byte disagreement here truncated every record and the host
    rejected all 469 of them."""
    assert HEADER_LEN == 23


def test_decodes_a_record():
    rec = parse_csi_record(record(bytes([1, 2, 3, 4])))
    assert rec.timestamp_us == 1234567
    assert rec.rssi_dbm == -60
    assert rec.noise_floor == -95
    assert rec.channel == 6
    assert rec.source_mac == "aa:bb:cc:dd:ee:ff"
    assert rec.rx_seq == 42
    assert rec.subcarriers == 2


def test_iq_pairs_are_real_then_imaginary_despite_the_wire_order():
    """The chip sends imaginary first. Getting this backwards conjugates every
    subcarrier and silently mirrors any phase-derived result."""
    rec = parse_csi_record(record(bytes([7, 3])))   # imag 7, real 3
    assert rec.iq() == [(3, 7)]


def test_negative_iq_values_survive():
    """The values are signed; reading them unsigned turns -1 into 255."""
    rec = parse_csi_record(record(bytes([0xFF, 0xFE])))
    assert rec.iq() == [(-2, -1)]


def test_amplitude_is_the_magnitude_of_the_pair():
    rec = parse_csi_record(record(bytes([4, 3])))   # imag 4, real 3
    assert rec.amplitudes() == [5.0]


def test_secondary_channel_is_split_out_of_the_phy_byte():
    rec = parse_csi_record(record(b"\x00\x00", phy=(2 << 4) | 3))
    assert rec.phy_format == 3
    assert rec.secondary_channel == 2


def test_first_word_invalid_is_reported_not_hidden():
    rec = parse_csi_record(record(b"\x01\x02", flags=FLAG_FIRST_WORD_INVALID))
    assert rec.first_word_invalid


def test_short_record_is_rejected():
    with pytest.raises(ValueError):
        parse_csi_record(b"\x00" * 10)


def test_record_claiming_more_data_than_it_carries_is_rejected():
    """Better to fail than to hand back a truncated channel response, which
    would look like a real measurement of a different channel."""
    with pytest.raises(ValueError, match="carries"):
        parse_csi_record(record(b"\x01\x02", declared=64))


def test_csv_row_keeps_one_record_on_one_line():
    """Subcarrier count varies with the PHY of each frame, so the pairs go in
    a single field rather than a variable number of columns."""
    row = to_csv_row(parse_csi_record(record(bytes([1, 2, 3, 4]))))
    assert "\n" not in row
    assert row.count(",") == CSV_HEADER.count(",")
    assert row.endswith("2:1 4:3")
