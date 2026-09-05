"""Wire framing for the ESP32-C6 sniffer link.

This is the authoritative definition of the wire format. ``firmware/main/frame.c``
mirrors it and is held to byte-identical output by the golden vectors in
``tests/vectors/golden.json``.

Wire format, little-endian throughout, 10-byte header::

    offset  size  field
    0       2     magic     0x5AC6
    2       1     type      FrameType
    3       1     flags     reserved, 0
    4       2     seq       wraps at 65536
    6       2     length    payload bytes, <= MAX_PAYLOAD
    8       2     hdr_crc   CRC-16/CCITT-FALSE over bytes 0..7
    10      N     payload

The CRC covers the header only. Payload integrity is already provided by the
radio FCS and by USB's own per-packet CRC, and the ESP32-C6 has no CRC
peripheral, so a payload CRC would cost real CPU for no benefit.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

MAGIC = 0x5AC6
HEADER_LEN = 10
MAX_PAYLOAD = 4096

_HEADER_STRUCT = struct.Struct("<HBBHH")  # magic, type, flags, seq, length


class FrameError(Exception):
    """Raised when bytes do not form a valid frame."""


class FrameType(IntEnum):
    PACKET = 1
    LOG = 2
    STATS = 3
    HEARTBEAT = 4
    CONTROL_REPLY = 5
    CONTROL_CMD = 6
    AP_RECORD = 7
    CSI = 8


@dataclass(frozen=True)
class Frame:
    ftype: FrameType
    seq: int
    payload: bytes
    flags: int = 0


def crc16_ccitt_false(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final XOR.

    Implemented explicitly rather than using ``esp_rom_crc16_le`` on the firmware
    side, whose reflection and final-XOR behaviour would have to be matched here
    exactly. Over an 8-byte header this is 64 iterations, which is negligible.
    """
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def encode_frame(ftype: FrameType, seq: int, payload: bytes, flags: int = 0) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise FrameError(f"payload {len(payload)} exceeds MAX_PAYLOAD {MAX_PAYLOAD}")
    header = _HEADER_STRUCT.pack(
        MAGIC, int(ftype), flags & 0xFF, seq & 0xFFFF, len(payload)
    )
    return header + struct.pack("<H", crc16_ccitt_false(header)) + payload


def decode_frame(buf: bytes) -> Frame:
    """Decode exactly one frame from the start of ``buf``. Raises FrameError."""
    if len(buf) < HEADER_LEN:
        raise FrameError("buffer shorter than header")
    magic, ftype, flags, seq, length = _HEADER_STRUCT.unpack(buf[:8])
    if magic != MAGIC:
        raise FrameError(f"bad magic {magic:#06x}")
    expected_crc = struct.unpack("<H", buf[8:10])[0]
    if crc16_ccitt_false(buf[:8]) != expected_crc:
        raise FrameError("header CRC mismatch")
    if length > MAX_PAYLOAD:
        raise FrameError(f"length {length} exceeds MAX_PAYLOAD")
    if len(buf) < HEADER_LEN + length:
        raise FrameError("buffer shorter than declared payload")
    try:
        ftype_enum = FrameType(ftype)
    except ValueError as exc:
        raise FrameError(f"unknown frame type {ftype}") from exc
    return Frame(
        ftype=ftype_enum,
        seq=seq,
        payload=buf[HEADER_LEN : HEADER_LEN + length],
        flags=flags,
    )
