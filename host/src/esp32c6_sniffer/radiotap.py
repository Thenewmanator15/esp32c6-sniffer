"""Radiotap headers for 802.11 capture, link type 127.

Wireshark dissects radiotap natively. The header is a small self-describing
block placed before each frame, carrying the radio metadata that the 802.11
frame itself does not: which channel it arrived on, how strong it was, and the
noise floor it arrived against.

Layout::

    u8   version   always 0
    u8   pad       always 0
    u16  length    whole radiotap header including this field, little-endian
    u32  present   bitmap of which fields follow
    ...  fields    in bit order, each aligned to its own natural size

**Alignment is the trap.** Every field must start at an offset that is a
multiple of its own size, with zero padding inserted to achieve it. A 64-bit
timestamp needs 8-byte alignment, a 16-bit channel needs 2-byte. Get it wrong
and Wireshark reads adjacent bytes as the value, producing plausible nonsense
rather than an error. The builder below inserts padding explicitly and the
tests assert every field's offset.

Field order in the buffer must also match ascending bit order in the present
bitmap; radiotap has no per-field tags.
"""

from __future__ import annotations

import struct

LINKTYPE_IEEE802_11_RADIOTAP = 127

# Present-bitmap bit positions, from the radiotap specification.
BIT_TSFT = 0
BIT_FLAGS = 1
BIT_RATE = 2
BIT_CHANNEL = 3
BIT_DBM_ANTSIGNAL = 5
BIT_DBM_ANTNOISE = 6
BIT_MCS = 19
BIT_AMPDU = 20
BIT_HE = 23

# Channel flags.
CHAN_2GHZ = 0x0080
CHAN_CCK = 0x0020
CHAN_OFDM = 0x0040

# Frame flags.
FLAG_FCS_AT_END = 0x10
FLAG_BAD_FCS = 0x40


class PhyFormat:
    """`cur_bb_format` from the C6's receive descriptor.

    Values match wifi_rx_bb_format_t in esp_wifi_he_types.h.
    """

    B = 0
    G = 1          # also 11a, same encoding
    HT = 2         # 11n
    VHT = 3        # 11ac
    HE_SU = 4
    HE_MU = 5
    HE_ERSU = 6
    HE_TB = 7
    VHT_MU = 11


# 11b transmission rates, in 500 kbps units as radiotap wants them. The radio
# reports a 5-bit encoding; only the four DSSS/CCK rates are meaningful here.
_CCK_RATES = {0: 2, 1: 4, 2: 11, 3: 22}   # 1, 2, 5.5, 11 Mbit/s

# The L-SIG RATE field, 4 bits, for OFDM frames. Again in 500 kbps units.
_LSIG_RATES = {
    0xB: 12, 0xF: 18, 0xA: 24, 0xE: 36,
    0x9: 48, 0xD: 72, 0x8: 96, 0xC: 108,
}


# radiotap MCS "known" bits.
MCS_KNOWN_BANDWIDTH = 0x01
MCS_KNOWN_INDEX = 0x02
MCS_KNOWN_GI = 0x04
MCS_KNOWN_FEC = 0x10
MCS_KNOWN_STBC = 0x20

# radiotap MCS flags.
MCS_BW_20 = 0
MCS_BW_40 = 1
MCS_BW_20L = 2   # 20 MHz lower half of a 40 MHz channel
MCS_BW_20U = 3   # 20 MHz upper half
MCS_FLAG_SGI = 0x04
MCS_FLAG_LDPC = 0x10
MCS_STBC_SHIFT = 5

#: Highest defined HT modulation-and-coding index.
HT_MCS_MAX = 76

#: Highest HE index this decoder will accept. HE-MCS runs 0-11.
HE_MCS_MAX = 11

# radiotap HE field, six u16 words. Only the bits actually filled are named.
HE_DATA1_FORMAT_SU = 0x0000
HE_DATA1_BSS_COLOR_KNOWN = 0x0004
HE_DATA1_UL_DL_KNOWN = 0x0010
HE_DATA1_MCS_KNOWN = 0x0020
HE_DATA1_DCM_KNOWN = 0x0040
HE_DATA2_BW_RU_KNOWN = 0x0004
HE_DATA2_GI_KNOWN = 0x0002
HE_DATA3_BSS_COLOR_MASK = 0x003F
HE_DATA3_UL_DL = 0x0080
HE_DATA3_MCS_SHIFT = 8
HE_DATA3_DCM = 0x1000
HE_DATA5_BW_MASK = 0x000F
HE_DATA5_GI_SHIFT = 4


def decode_he_sig_a(sig1: int, sig2: int):
    """Decodes HE-SIG-A into radiotap HE words, or returns None.

    HE-SIG-A1 for a single-user PPDU: bit 0 Format, bit 1 Beam Change, bit 2
    UL/DL, bits 3-6 MCS, bit 7 DCM, bits 8-13 BSS Color, bits 15-18 Spatial
    Reuse, bits 19-20 Bandwidth, bits 21-22 GI and LTF size.

    Two checks guard against a wrong bit layout reaching the capture, in the
    same spirit as the HT decode's length check: the Format bit must be set,
    because the radio only labels a frame HE when it is, and the index must be
    within the 0-11 that HE defines. Either failing means None and no HE field
    at all, rather than a confident wrong modulation on every 11ax frame.
    """
    if not sig1 & 0x01:
        return None
    mcs = (sig1 >> 3) & 0x0F
    if mcs > HE_MCS_MAX:
        return None

    bss_color = (sig1 >> 8) & 0x3F
    dcm = (sig1 >> 7) & 0x01
    ul_dl = (sig1 >> 2) & 0x01
    bandwidth = (sig1 >> 19) & 0x03
    gi_ltf = (sig1 >> 21) & 0x03

    data1 = (HE_DATA1_FORMAT_SU | HE_DATA1_BSS_COLOR_KNOWN
             | HE_DATA1_UL_DL_KNOWN | HE_DATA1_MCS_KNOWN
             | HE_DATA1_DCM_KNOWN)
    data2 = HE_DATA2_BW_RU_KNOWN | HE_DATA2_GI_KNOWN
    data3 = (bss_color & HE_DATA3_BSS_COLOR_MASK)
    data3 |= (mcs << HE_DATA3_MCS_SHIFT)
    if dcm:
        data3 |= HE_DATA3_DCM
    if ul_dl:
        data3 |= HE_DATA3_UL_DL
    data4 = 0
    data5 = (bandwidth & HE_DATA5_BW_MASK) | (gi_ltf << HE_DATA5_GI_SHIFT)
    data6 = 0
    return (data1, data2, data3, data4, data5, data6)


def decode_ht_sig(sig1: int, sig2: int, expected_length: int):
    """Decodes HT-SIG into radiotap MCS fields, or returns None.

    HT-SIG1 is MCS in bits 0-6, 20/40 bandwidth in bit 7, and the HT Length in
    bits 8-23. HT-SIG2 carries aggregation, STBC, FEC and the short guard
    interval in bits 3, 4-5, 6 and 7.

    **The length is used as a self-check.** This decode has not been confirmed
    against live 11n traffic, so rather than trust the bit layout, the HT Length
    it yields is compared with the length the radio actually reported. They come
    from independent places -- one from the signal field, one from the receive
    descriptor -- so agreement is strong evidence the layout is right, and
    disagreement means None and no MCS is claimed. That is deliberate: a
    plausible wrong MCS on every 11n frame is worse than no MCS at all.
    """
    mcs = sig1 & 0x7F
    if mcs > HT_MCS_MAX:
        return None
    if ((sig1 >> 8) & 0xFFFF) != expected_length:
        return None

    known = MCS_KNOWN_INDEX | MCS_KNOWN_BANDWIDTH | MCS_KNOWN_GI
    known |= MCS_KNOWN_FEC | MCS_KNOWN_STBC

    flags = MCS_BW_40 if (sig1 >> 7) & 1 else MCS_BW_20
    if (sig2 >> 7) & 1:
        flags |= MCS_FLAG_SGI
    if (sig2 >> 6) & 1:
        flags |= MCS_FLAG_LDPC
    flags |= ((sig2 >> 4) & 0x03) << MCS_STBC_SHIFT

    return known, flags, mcs


def rate_500kbps(phy_format: int, rate_code: int) -> int | None:
    """Radiotap Rate for a legacy frame, or None when it cannot be expressed.

    HT, VHT and HE frames carry a modulation-and-coding index, not a legacy
    rate, and radiotap has separate fields for those. Emitting the Rate field
    anyway would put a plausible but wrong number in front of every 11n and
    11ax frame, so those return None and the field is omitted.
    """
    if phy_format == PhyFormat.B:
        return _CCK_RATES.get(rate_code & 0x1F)
    if phy_format == PhyFormat.G:
        return _LSIG_RATES.get(rate_code & 0x0F)
    return None

_HEADER = struct.Struct("<BBHI")
HEADER_LEN = _HEADER.size  # 8


def channel_frequency_mhz(channel: int) -> int:
    """2.4 GHz band. Channel 14 is the exception, 12 MHz above channel 13."""
    if not 1 <= channel <= 14:
        raise ValueError(f"channel {channel} outside the 2.4 GHz range 1-14")
    if channel == 14:
        return 2484
    return 2407 + 5 * channel


def build_radiotap(
    *,
    channel: int,
    rssi_dbm: int,
    noise_dbm: int | None = None,
    timestamp_us: int | None = None,
    ofdm: bool = True,
    bad_fcs: bool = False,
    fcs_present: bool = False,
    rate_500kbps_units: int | None = None,
    mcs: tuple[int, int, int] | None = None,
    ampdu_reference: int | None = None,
    he: tuple[int, int, int, int, int, int] | None = None,
) -> bytes:
    """Builds a radiotap header. Returns the bytes to prepend to the frame.

    `ofdm` selects the channel's modulation flag; pass False for 11b, which is
    CCK. `rate_500kbps_units` adds the Rate field, and should be omitted for
    HT/VHT/HE frames whose rate radiotap cannot express here.
    """
    if not -128 <= rssi_dbm <= 127:
        raise ValueError(f"rssi {rssi_dbm} outside a signed byte")
    if noise_dbm is not None and not -128 <= noise_dbm <= 127:
        raise ValueError(f"noise {noise_dbm} outside a signed byte")

    present = 0
    body = bytearray()

    def align(size: int) -> None:
        # Offsets are measured from the start of the whole header, not the body.
        pad = (-(HEADER_LEN + len(body))) % size
        body.extend(b"\x00" * pad)

    if timestamp_us is not None:
        present |= 1 << BIT_TSFT
        align(8)
        body.extend(struct.pack("<Q", timestamp_us & 0xFFFFFFFFFFFFFFFF))

    present |= 1 << BIT_FLAGS
    flags = 0
    if fcs_present:
        flags |= FLAG_FCS_AT_END
    if bad_fcs:
        flags |= FLAG_BAD_FCS
    body.append(flags)

    if rate_500kbps_units is not None:
        # Bit 2, so it must be written after FLAGS and before CHANNEL: fields
        # appear in ascending bit order and radiotap has no per-field tags.
        if not 0 < rate_500kbps_units <= 0xFF:
            raise ValueError(f"rate {rate_500kbps_units} outside a byte")
        present |= 1 << BIT_RATE
        body.append(rate_500kbps_units)

    present |= 1 << BIT_CHANNEL
    align(2)
    chan_flags = CHAN_2GHZ | (CHAN_OFDM if ofdm else CHAN_CCK)
    body.extend(struct.pack("<HH", channel_frequency_mhz(channel), chan_flags))

    present |= 1 << BIT_DBM_ANTSIGNAL
    body.extend(struct.pack("<b", rssi_dbm))

    if noise_dbm is not None:
        present |= 1 << BIT_DBM_ANTNOISE
        body.extend(struct.pack("<b", noise_dbm))

    if mcs is not None:
        # Bit 19, so it follows everything above; three bytes, no alignment.
        present |= 1 << BIT_MCS
        body.extend(bytes(mcs))

    if ampdu_reference is not None:
        # Bit 20: a 32-bit reference shared by the subframes of one aggregate,
        # then flags and two reserved bytes. Wireshark groups by the reference,
        # which is what makes an A-MPDU readable as one transmission rather
        # than twenty unrelated frames.
        present |= 1 << BIT_AMPDU
        align(4)
        body.extend(struct.pack("<IHBB", ampdu_reference & 0xFFFFFFFF, 0, 0, 0))

    if he is not None:
        present |= 1 << BIT_HE
        align(2)
        body.extend(struct.pack("<6H", *he))

    return _HEADER.pack(0, 0, HEADER_LEN + len(body), present) + bytes(body)
