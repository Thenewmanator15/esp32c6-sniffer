"""PACKET_BATCH and LINK payloads.

This is the authoritative definition of both layouts, as ``framing.py`` is for
the frame header. The firmware mirrors it and is held to byte-identical output
by the golden vectors in ``tests/vectors/golden.json``.

Why batching exists: a PACKET frame costs 10 bytes of header plus 12 bytes of
metadata per captured packet, so a 5-byte 802.15.4 acknowledgement travels as
27 bytes. On the nRF54L15 the link to the host is a UART through the board's
SAMD11 bridge, measured at 94 kB/s, and worst-case BLE connection-following
needs about 128 kB/s at that overhead. Batching brings the overhead to about
5.6 bytes per packet -- one frame header shared across up to 32 packets, the
channel stated once, timestamps as 16-bit deltas -- which is most of the gap.

Every packet keeps its own capture timestamp, reconstructed exactly from the
deltas, so nothing about timing accuracy changes. Wireshark shows capture
time, not arrival time.

PACKET_BATCH payload, little-endian::

    offset  size  field
    0       8     base_timestamp_us   the first packet's capture time
    8       1     channel             one per batch; a change closes the batch
    9       1     count               1..32
    10      ...   count entries:
              2   dt_us               delta from the previous entry; for the
                                      first entry, from base_timestamp_us
              1   lqi
              1   rssi_dbm            signed
              1   len                 0..127
              len psdu

There is no flags byte. It is always zero today on both boards -- the drivers
strip the FCS before we see a frame, so SN_154_FLAG_HAS_FCS is never set --
and reintroducing it would cost a byte per packet for nothing.

BLE_BATCH payload, little-endian::

    offset  size  field
    0       8     base_timestamp_us   the first packet's arrival time
    8       1     count               1..32
    9       ...   count entries:
              2   dt_us               delta from the previous entry; for the
                                      first entry, from base_timestamp_us
              2   orig_len            H4 length before any truncation
              1   flags               SN_BLE_FLAG_TRUNCATED is bit 0
              2   len                 bytes actually carried
              len hci                 starting with the H4 packet-type byte

``len`` is sixteen bits because an HCI event does not fit in eight. Its own
parameter-length field is a byte, so the H4 packet reaches 258 bytes: one type
byte, a two-byte event header, and up to 255 of parameters. An eight-bit field
wrapped modulo 256 and the decoder lost alignment mid-batch, which surfaced as
trailing bytes rather than as anything naming the length.

There is no channel. BLE advertises on three and the controller rotates
them without reporting which one it heard, so there is nothing to state.

This is a separate layout from PACKET_BATCH rather than a variant of it. An
802.15.4 entry carries a channel, an LQI and an RSSI; a BLE entry carries an
HCI event whose own header already holds the address and signal strength.

LINK payload, little-endian::

    0       4     queued_bytes        waiting in the board's outbound ring now
    4       4     high_water          the most it has held this session
    8       4     capacity

Occupancy only. Frames refused because the ring was full are counted in the
STATS frame's ``frames_dropped_ringfull``, which already reaches the pcapng
interface-statistics blocks; carrying them here too would double-count.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

BATCH_HEADER = struct.Struct("<QBB")   # base_timestamp_us, channel, count
BATCH_ENTRY = struct.Struct("<HBbB")   # dt_us, lqi, rssi_dbm, len
BLE_BATCH_HEADER = struct.Struct("<QB")     # base_timestamp_us, count
BLE_BATCH_ENTRY = struct.Struct("<HHBH")    # dt_us, orig_len, flags, len
LINK_STATUS = struct.Struct("<III")    # queued_bytes, high_water, capacity

BATCH_HEADER_LEN = BATCH_HEADER.size
BATCH_ENTRY_LEN = BATCH_ENTRY.size
LINK_LEN = LINK_STATUS.size

BLE_BATCH_HEADER_LEN = BLE_BATCH_HEADER.size
BLE_BATCH_ENTRY_LEN = BLE_BATCH_ENTRY.size

MAX_BATCH_ENTRIES = 32
#: The largest H4 packet a board forwards, matching SN_BLE_MAX_PACKET in both
#: firmwares. Longer events are truncated and flagged rather than dropped.
#: An HCI event cannot actually exceed 258 -- a type byte, a two-byte header
#: and a parameter length that is itself only a byte -- so this is headroom
#: rather than a limit anything reaches.
MAX_HCI = 300
#: An 802.15.4 PSDU is at most 127 bytes.
MAX_PSDU = 127
#: The largest delta a 16-bit field can carry. A gap wider than this closes the
#: batch and starts another; it does not truncate.
MAX_DT_US = 0xFFFF


class BatchError(ValueError):
    """Raised when bytes do not form a valid batch or link payload."""


@dataclass(frozen=True)
class BatchEntry:
    """One captured packet as it appears inside a batch.

    ``timestamp_us`` is ABSOLUTE, in the board's microsecond clock. The delta
    coding is an encoding detail and never leaks out of this module.
    """

    timestamp_us: int
    lqi: int
    rssi_dbm: int
    psdu: bytes


@dataclass(frozen=True)
class LinkStatus:
    queued_bytes: int
    high_water: int
    capacity: int


def encode_packet_batch(channel: int, entries: list[BatchEntry]) -> bytes:
    """Builds a PACKET_BATCH payload.

    Entries must be in capture order with non-decreasing timestamps, and no
    two consecutive timestamps may differ by more than MAX_DT_US. Those are
    the conditions under which the firmware closes a batch, so an encoder
    that accepted otherwise would produce payloads no firmware would.
    """
    if not 1 <= len(entries) <= MAX_BATCH_ENTRIES:
        raise BatchError(f"count {len(entries)} outside 1-{MAX_BATCH_ENTRIES}")
    if not 0 <= channel <= 0xFF:
        raise BatchError(f"channel {channel} does not fit in a byte")

    base = entries[0].timestamp_us
    out = bytearray(BATCH_HEADER.pack(base, channel, len(entries)))
    prev = base
    for entry in entries:
        dt = entry.timestamp_us - prev
        if dt < 0:
            raise BatchError("timestamps must not go backwards within a batch")
        if dt > MAX_DT_US:
            raise BatchError(f"delta {dt} us exceeds {MAX_DT_US}; close the batch")
        if len(entry.psdu) > MAX_PSDU:
            raise BatchError(f"psdu {len(entry.psdu)} exceeds {MAX_PSDU}")
        if not 0 <= entry.lqi <= 0xFF:
            raise BatchError(f"lqi {entry.lqi} does not fit in a byte")
        if not -128 <= entry.rssi_dbm <= 127:
            raise BatchError(f"rssi {entry.rssi_dbm} does not fit in a signed byte")
        out += BATCH_ENTRY.pack(dt, entry.lqi, entry.rssi_dbm, len(entry.psdu))
        out += entry.psdu
        prev = entry.timestamp_us
    return bytes(out)


def decode_packet_batch(payload: bytes) -> tuple[int, list[BatchEntry]]:
    """Returns (channel, entries) with absolute timestamps reconstructed.

    A truncated or inconsistent payload raises rather than yielding a partial
    batch: half a batch decoded as though whole would be several frames with
    confident wrong timestamps, which is worse than one frame reported lost.
    """
    if len(payload) < BATCH_HEADER_LEN:
        raise BatchError("payload shorter than the batch header")
    base, channel, count = BATCH_HEADER.unpack_from(payload)
    if not 1 <= count <= MAX_BATCH_ENTRIES:
        raise BatchError(f"count {count} outside 1-{MAX_BATCH_ENTRIES}")

    entries: list[BatchEntry] = []
    at = BATCH_HEADER_LEN
    ts = base
    for _ in range(count):
        if len(payload) - at < BATCH_ENTRY_LEN:
            raise BatchError("payload ends inside an entry header")
        dt, lqi, rssi, length = BATCH_ENTRY.unpack_from(payload, at)
        at += BATCH_ENTRY_LEN
        if length > MAX_PSDU:
            raise BatchError(f"psdu length {length} exceeds {MAX_PSDU}")
        if len(payload) - at < length:
            raise BatchError("payload ends inside a psdu")
        ts += dt
        entries.append(BatchEntry(ts, lqi, rssi, bytes(payload[at:at + length])))
        at += length
    if at != len(payload):
        raise BatchError(f"{len(payload) - at} trailing bytes after the last entry")
    return channel, entries


@dataclass(frozen=True)
class BleBatchEntry:
    """One captured BLE packet as it appears inside a batch.

    ``timestamp_us`` is ABSOLUTE, in the board's microsecond clock; the delta
    coding never leaves this module. ``hci`` starts with its H4 packet-type
    byte, and ``orig_len`` is what its length was before any truncation, so a
    truncated entry still reports how much it lost.
    """

    timestamp_us: int
    orig_len: int
    flags: int
    hci: bytes


def encode_ble_batch(entries: list[BleBatchEntry]) -> bytes:
    """Builds a BLE_BATCH payload.

    The same ordering rules as a PACKET_BATCH, and for the same reason: these
    are the conditions under which the firmware closes a batch, so an encoder
    that accepted otherwise would produce payloads no firmware would send.
    """
    if not 1 <= len(entries) <= MAX_BATCH_ENTRIES:
        raise BatchError(f"count {len(entries)} outside 1-{MAX_BATCH_ENTRIES}")

    base = entries[0].timestamp_us
    out = bytearray(BLE_BATCH_HEADER.pack(base, len(entries)))
    prev = base
    for entry in entries:
        dt = entry.timestamp_us - prev
        if dt < 0:
            raise BatchError("timestamps must not go backwards within a batch")
        if dt > MAX_DT_US:
            raise BatchError(f"delta {dt} us exceeds {MAX_DT_US}; close the batch")
        if len(entry.hci) > MAX_HCI:
            raise BatchError(f"hci {len(entry.hci)} exceeds {MAX_HCI}")
        if not 0 <= entry.orig_len <= 0xFFFF:
            raise BatchError(f"orig_len {entry.orig_len} does not fit in 16 bits")
        if entry.orig_len < len(entry.hci):
            raise BatchError("orig_len is smaller than the bytes carried")
        if not 0 <= entry.flags <= 0xFF:
            raise BatchError(f"flags {entry.flags} does not fit in a byte")
        out += BLE_BATCH_ENTRY.pack(dt, entry.orig_len, entry.flags,
                                    len(entry.hci))
        out += entry.hci
        prev = entry.timestamp_us
    return bytes(out)


def decode_ble_batch(payload: bytes) -> list[BleBatchEntry]:
    """Returns the entries with absolute timestamps reconstructed.

    Raises rather than yielding a partial batch, for the reason
    ``decode_packet_batch`` does: several frames with confident wrong
    timestamps is worse than one frame reported lost.
    """
    if len(payload) < BLE_BATCH_HEADER_LEN:
        raise BatchError("payload shorter than the batch header")
    base, count = BLE_BATCH_HEADER.unpack_from(payload)
    if not 1 <= count <= MAX_BATCH_ENTRIES:
        raise BatchError(f"count {count} outside 1-{MAX_BATCH_ENTRIES}")

    entries: list[BleBatchEntry] = []
    at = BLE_BATCH_HEADER_LEN
    ts = base
    for _ in range(count):
        if len(payload) - at < BLE_BATCH_ENTRY_LEN:
            raise BatchError("payload ends inside an entry header")
        dt, orig_len, flags, length = BLE_BATCH_ENTRY.unpack_from(payload, at)
        at += BLE_BATCH_ENTRY_LEN
        if length > MAX_HCI:
            raise BatchError(f"hci length {length} exceeds {MAX_HCI}")
        if len(payload) - at < length:
            raise BatchError("payload ends inside an hci packet")
        ts += dt
        entries.append(BleBatchEntry(ts, orig_len, flags,
                                     bytes(payload[at:at + length])))
        at += length
    if at != len(payload):
        raise BatchError(f"{len(payload) - at} trailing bytes after the last entry")
    return entries


def encode_link(queued_bytes: int, high_water: int, capacity: int) -> bytes:
    for name, value in (("queued_bytes", queued_bytes),
                        ("high_water", high_water),
                        ("capacity", capacity)):
        if not 0 <= value <= 0xFFFFFFFF:
            raise BatchError(f"{name} {value} does not fit in 32 bits")
    return LINK_STATUS.pack(queued_bytes, high_water, capacity)


def decode_link(payload: bytes) -> LinkStatus:
    if len(payload) != LINK_LEN:
        raise BatchError(f"link payload is {len(payload)} bytes, expected {LINK_LEN}")
    return LinkStatus(*LINK_STATUS.unpack(payload))
