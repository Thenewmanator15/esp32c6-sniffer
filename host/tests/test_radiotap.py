import struct

import pytest

from esp32c6_sniffer.radiotap import (
    BIT_CHANNEL,
    BIT_DBM_ANTNOISE,
    BIT_DBM_ANTSIGNAL,
    BIT_FLAGS,
    BIT_TSFT,
    HEADER_LEN,
    LINKTYPE_IEEE802_11_RADIOTAP,
    build_radiotap,
    channel_frequency_mhz,
)


def test_linktype_is_the_registered_value():
    assert LINKTYPE_IEEE802_11_RADIOTAP == 127


def test_version_and_pad_are_zero():
    rt = build_radiotap(channel=6, rssi_dbm=-50)
    assert rt[0] == 0
    assert rt[1] == 0


def test_declared_length_matches_actual():
    rt = build_radiotap(channel=6, rssi_dbm=-50, noise_dbm=-95,
                        timestamp_us=123456789)
    assert struct.unpack_from("<H", rt, 2)[0] == len(rt)


def test_present_bitmap_lists_exactly_what_was_supplied():
    rt = build_radiotap(channel=1, rssi_dbm=-40)
    present = struct.unpack_from("<I", rt, 4)[0]
    assert present & (1 << BIT_FLAGS)
    assert present & (1 << BIT_CHANNEL)
    assert present & (1 << BIT_DBM_ANTSIGNAL)
    assert not present & (1 << BIT_TSFT), "no timestamp was given"
    assert not present & (1 << BIT_DBM_ANTNOISE), "no noise floor was given"


def test_optional_fields_appear_when_supplied():
    rt = build_radiotap(channel=1, rssi_dbm=-40, noise_dbm=-92,
                        timestamp_us=42)
    present = struct.unpack_from("<I", rt, 4)[0]
    assert present & (1 << BIT_TSFT)
    assert present & (1 << BIT_DBM_ANTNOISE)


def test_timestamp_is_eight_byte_aligned():
    """Radiotap aligns every field to its own size. Get this wrong and
    Wireshark reads adjacent bytes as the value, silently."""
    rt = build_radiotap(channel=6, rssi_dbm=-50, timestamp_us=0x1122334455667788)
    # TSFT is the first field, so it starts right after the 8-byte header.
    assert HEADER_LEN % 8 == 0
    assert struct.unpack_from("<Q", rt, HEADER_LEN)[0] == 0x1122334455667788


def test_channel_is_two_byte_aligned_with_padding_inserted():
    # Without a timestamp: header 8, flags 1 byte at 8, so channel must be
    # padded from offset 9 to 10.
    rt = build_radiotap(channel=11, rssi_dbm=-50)
    freq = struct.unpack_from("<H", rt, 10)[0]
    assert freq == channel_frequency_mhz(11)


def test_signal_reads_back_as_a_signed_byte():
    rt = build_radiotap(channel=6, rssi_dbm=-73)
    # flags at 8, pad at 9, channel freq 10-11, channel flags 12-13, signal 14
    assert struct.unpack_from("<b", rt, 14)[0] == -73


@pytest.mark.parametrize(
    "channel,freq",
    [(1, 2412), (6, 2437), (11, 2462), (13, 2472), (14, 2484)],
)
def test_channel_frequencies(channel, freq):
    """Channel 14 is the exception: 12 MHz above 13, not 5."""
    assert channel_frequency_mhz(channel) == freq


@pytest.mark.parametrize("channel", [0, 15, 36, 99])
def test_rejects_channels_outside_the_24ghz_band(channel):
    with pytest.raises(ValueError):
        channel_frequency_mhz(channel)


def test_rejects_out_of_range_signal():
    with pytest.raises(ValueError):
        build_radiotap(channel=6, rssi_dbm=-500)


def test_length_is_stable_for_the_same_inputs():
    a = build_radiotap(channel=6, rssi_dbm=-50, noise_dbm=-95)
    b = build_radiotap(channel=6, rssi_dbm=-50, noise_dbm=-95)
    assert a == b
