"""Classic pcap writer.

Deliberately the original pcap format rather than pcapng. Wireshark reads both,
the format is a fixed 24-byte file header plus a 16-byte record header, and it
streams cleanly into a pipe without the block bookkeeping pcapng needs. The
extcap plugin writes into a named pipe that Wireshark reads live, so a format
with no back-references is worth more here than pcapng's extra metadata.

File header, 24 bytes, native byte order (we always write little-endian)::

    magic_number   4  0xA1B2C3D4  (0xA1B23C4D would mean nanosecond timestamps)
    version_major  2  2
    version_minor  2  4
    thiszone       4  GMT offset, always 0
    sigfigs        4  timestamp accuracy, always 0
    snaplen        4  max captured length per packet
    network        4  link type

Record header, 16 bytes, per packet::

    ts_sec         4  seconds since the Unix epoch
    ts_usec        4  microseconds within the second
    incl_len       4  bytes actually stored
    orig_len       4  bytes originally on the wire
"""

from __future__ import annotations

import struct
from typing import BinaryIO

PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
DEFAULT_SNAPLEN = 262144

_FILE_HEADER = struct.Struct("<IHHiIII")
_RECORD_HEADER = struct.Struct("<IIII")


class PcapWriter:
    """Writes a classic pcap stream. Flushes per packet so live capture updates."""

    def __init__(
        self,
        stream: BinaryIO,
        linktype: int,
        snaplen: int = DEFAULT_SNAPLEN,
    ) -> None:
        self._stream = stream
        self._snaplen = snaplen
        self._stream.write(
            _FILE_HEADER.pack(
                PCAP_MAGIC_MICROSECONDS,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,  # thiszone
                0,  # sigfigs
                snaplen,
                linktype,
            )
        )

    def write_packet(
        self,
        data: bytes,
        timestamp_s: float,
        original_length: int | None = None,
    ) -> None:
        """Append one packet.

        `original_length` records the on-air size when `data` has been truncated
        by a snapshot length. Wireshark shows the difference, so a truncated
        capture is visibly truncated rather than silently short.
        """
        stored = data[: self._snaplen]
        orig = original_length if original_length is not None else len(data)
        ts_sec = int(timestamp_s)
        ts_usec = int(round((timestamp_s - ts_sec) * 1_000_000))
        # Rounding can carry into the next second.
        if ts_usec >= 1_000_000:
            ts_sec += 1
            ts_usec -= 1_000_000
        self._stream.write(
            _RECORD_HEADER.pack(ts_sec, ts_usec, len(stored), orig)
        )
        self._stream.write(stored)

    def flush(self) -> None:
        self._stream.flush()
