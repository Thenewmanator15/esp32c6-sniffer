"""Channel state information records.

CSI is the per-subcarrier channel response for a received frame: complex
amplitude and phase per subcarrier, of which RSSI is a single-number summary.
It is what Wi-Fi sensing work is built on -- motion, presence, respiration,
coarse positioning -- because a person moving through a room changes the
multipath, and that shows up here long before it shows up in RSSI.

No pcap link type has anywhere to put this, and inventing a place inside
radiotap would produce captures only this project could read. So records travel
as their own frame type and are written beside the pcap, sharing its timestamps
so the two can be lined up afterwards.

Wire layout, little-endian, matching csi_cb() in firmware/main/radio80211.c::

    uint64 timestamp_us
    int8   rssi_dbm
    int8   noise_floor
    uint8  channel
    uint8  phy           low nibble format, high nibble secondary channel
    uint8  mac[6]        source
    uint16 rx_seq
    uint8  flags
    uint16 csi_len
    int8   csi[csi_len]  interleaved, imaginary first

The values are signed 8-bit pairs. On this chip they are **imaginary first,
then real**, which is the opposite of the order most people assume; getting it
backwards conjugates every subcarrier and quietly mirrors any phase-derived
result.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

_HEADER = struct.Struct("<QbbBB6sHBH")
HEADER_LEN = _HEADER.size  # 22

#: The first four bytes are unusable on some frames, a hardware limitation the
#: driver reports rather than hides.
FLAG_FIRST_WORD_INVALID = 0x01


@dataclass(frozen=True)
class CsiRecord:
    timestamp_us: int
    rssi_dbm: int
    noise_floor: int
    channel: int
    phy_format: int
    secondary_channel: int
    source_mac: str
    rx_seq: int
    first_word_invalid: bool
    raw: bytes

    @property
    def subcarriers(self) -> int:
        return len(self.raw) // 2

    def iq(self) -> list[tuple[int, int]]:
        """Returns (real, imaginary) pairs, one per subcarrier.

        The wire order is imaginary first. Swapping them here rather than at
        every call site means a phase computed downstream has the sign the
        caller expects.
        """
        pairs = []
        data = self.raw
        for i in range(0, len(data) - 1, 2):
            imag = data[i] - 256 if data[i] > 127 else data[i]
            real = data[i + 1] - 256 if data[i + 1] > 127 else data[i + 1]
            pairs.append((real, imag))
        return pairs

    def amplitudes(self) -> list[float]:
        """Per-subcarrier magnitude. The usual starting point for sensing."""
        return [(r * r + i * i) ** 0.5 for r, i in self.iq()]


def parse_csi_record(payload: bytes) -> CsiRecord:
    """Decodes one CSI frame payload.

    Raises ValueError when the record is shorter than it claims, rather than
    returning a silently truncated channel response, which would look like a
    real measurement of a different channel.
    """
    if len(payload) < HEADER_LEN:
        raise ValueError(
            f"CSI record is {len(payload)} bytes, need at least {HEADER_LEN}"
        )
    (timestamp, rssi, noise, channel, phy, mac, rx_seq, flags,
     csi_len) = _HEADER.unpack_from(payload)
    raw = payload[HEADER_LEN:HEADER_LEN + csi_len]
    if len(raw) != csi_len:
        raise ValueError(
            f"CSI record claims {csi_len} bytes of data but carries {len(raw)}"
        )
    return CsiRecord(
        timestamp_us=timestamp,
        rssi_dbm=rssi,
        noise_floor=noise,
        channel=channel,
        phy_format=phy & 0x0F,
        secondary_channel=(phy >> 4) & 0x0F,
        source_mac=":".join(f"{b:02x}" for b in mac),
        rx_seq=rx_seq,
        first_word_invalid=bool(flags & FLAG_FIRST_WORD_INVALID),
        raw=raw,
    )


CSV_HEADER = (
    "timestamp_us,source_mac,channel,rssi_dbm,noise_floor,rx_seq,"
    "phy_format,first_word_invalid,subcarriers,iq"
)


def to_csv_row(record: CsiRecord) -> str:
    """One record as a CSV line, with the I/Q pairs in the last field.

    The pairs are space-separated `real:imag` so the row stays one line
    whatever the subcarrier count, which varies with the PHY of each frame.
    """
    pairs = " ".join(f"{r}:{i}" for r, i in record.iq())
    return (
        f"{record.timestamp_us},{record.source_mac},{record.channel},"
        f"{record.rssi_dbm},{record.noise_floor},{record.rx_seq},"
        f"{record.phy_format},{int(record.first_word_invalid)},"
        f"{record.subcarriers},{pairs}"
    )
