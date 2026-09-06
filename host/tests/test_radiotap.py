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
    HE_DATA1_BW_RU_KNOWN,
    HE_DATA2_GI_KNOWN,
    HE_DATA2_NUM_LTF_KNOWN,
    HE_DATA3_BSS_COLOR_MASK,
    HE_DATA5_BW_MASK,
    HE_DATA5_GI_SHIFT,
    HE_DATA5_LTF_SIZE_SHIFT,
    build_radiotap,
    channel_frequency_mhz,
    decode_he_sig_a,
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


# --- HE-SIG-A to radiotap ----------------------------------------------------
#
# The bit positions below were taken from Wireshark's own field registry
# (`tshark -G fields`, which lists the flags of each word in order) and then
# confirmed by round-tripping a synthetic capture back through tshark. Three
# faults were found that way, one per assertion group here. All three were
# silent: no exception, no malformed capture, just wrong or absent values.

def he_sig_a1(mcs=7, bss_color=0x1E, bandwidth=0, gi_ltf=0, dcm=0, ul_dl=0):
    return (1 | ((ul_dl & 1) << 2) | ((mcs & 0x0F) << 3) | ((dcm & 1) << 7)
            | ((bss_color & 0x3F) << 8) | ((bandwidth & 0x03) << 19)
            | ((gi_ltf & 0x03) << 21))


@pytest.mark.parametrize("bandwidth", [0, 1, 2, 3])
def test_bandwidth_is_declared_known_in_data1_not_data2(bandwidth):
    """data1 bit 14 is the bandwidth known-bit. Setting data2 bit 2 instead
    left the bandwidth populated but undeclared, so Wireshark showed nothing:
    the field came back empty for all 1286 HE frames of a real 11ax capture."""
    data1, _data2, _d3, _d4, data5, _d6 = decode_he_sig_a(
        he_sig_a1(bandwidth=bandwidth), 0)
    assert data1 & HE_DATA1_BW_RU_KNOWN
    assert data5 & HE_DATA5_BW_MASK == bandwidth


def test_no_claim_is_made_to_know_the_ltf_symbol_count():
    """HE-SIG-A does not carry one, and the field is left at zero, so the bit
    that says it is known must stay clear. Setting it published a confident
    count of zero on every HE frame."""
    _d1, data2, _d3, _d4, _d5, _d6 = decode_he_sig_a(he_sig_a1(), 0)
    assert not data2 & HE_DATA2_NUM_LTF_KNOWN


@pytest.mark.parametrize("gi_ltf,gi,ltf_size", [
    (0, 0, 1),      # 0.8 us guard interval, 1x LTF
    (1, 0, 2),      # 0.8 us -- NOT 1.6, which copying the raw field gave
    (2, 1, 2),      # 1.6 us
    (3, 2, 3),      # 3.2 us -- copying the raw field gave 3, "reserved"
])
def test_combined_gi_and_ltf_field_is_split_not_copied(gi_ltf, gi, ltf_size):
    """HE-SIG-A carries one field meaning both; radiotap has two, with
    different encodings. Only gi_ltf 0 survives a straight copy."""
    _d1, data2, _d3, _d4, data5, _d6 = decode_he_sig_a(
        he_sig_a1(gi_ltf=gi_ltf), 0)
    assert (data5 >> HE_DATA5_GI_SHIFT) & 0x03 == gi
    assert (data5 >> HE_DATA5_LTF_SIZE_SHIFT) & 0x03 == ltf_size
    assert data2 & HE_DATA2_GI_KNOWN       # this one IS carried, so may be
    assert (data5 >> HE_DATA5_GI_SHIFT) & 0x03 != 3   # never the reserved value


def test_every_known_bit_set_has_a_populated_field():
    """The general form of the two faults above: a known-bit is a promise, and
    promising a field that was never filled publishes a confident zero."""
    _d1, data2, data3, _d4, data5, _d6 = decode_he_sig_a(
        he_sig_a1(mcs=11, bss_color=0x3F, bandwidth=3, gi_ltf=3), 0)
    # Only bits whose fields this decoder fills may be set anywhere in data2.
    assert data2 == HE_DATA2_GI_KNOWN
    assert data3 & HE_DATA3_BSS_COLOR_MASK == 0x3F
    assert data5 & HE_DATA5_BW_MASK == 3
