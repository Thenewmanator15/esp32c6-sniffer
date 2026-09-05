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

    return _HEADER.pack(0, 0, HEADER_LEN + len(body), present) + bytes(body)
