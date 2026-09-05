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
) -> bytes:
    """Builds a radiotap header. Returns the bytes to prepend to the frame."""
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
