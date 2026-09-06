"""pcapng writer: captures that describe themselves.

Classic pcap carries a link type, a snapshot length and nothing else.
Everything worth knowing about a capture from this sniffer lives outside the
file: which board took it, on which firmware, how many frames the board dropped
before the host ever saw them, and -- for an encrypted mesh -- the key needed
to read it. A capture handed to somebody else arrives without any of that.

pcapng carries all of it in the file:

* the board, its firmware version and the radio, in the section and interface
  headers, so capinfos and Wireshark's Capture File Properties answer "what
  took this?" without a covering note;
* the board's own receive and drop counts, in an Interface Statistics Block
  written at close, so "did I miss anything?" is answerable months later from
  the file alone rather than from a toolbar log nobody kept;
* decryption keys, in a Decryption Secrets Block, so a Zigbee capture decrypts
  itself on any machine instead of requiring the recipient to paste a key into
  their own Wireshark preferences.

The block layout was taken from a file Wireshark itself wrote (editcap with
--inject-secrets) and parsed back, not from memory. Every block is::

    block type          4
    block total length  4   including both length fields, a multiple of 4
    body                n
    options             n   each: code 2, length 2, value, padded to 4
    block total length  4   repeated, so a reader can walk backwards

The secrets-type constants are four-character codes stored as 32-bit integers.
They were read out of the shipped libwiretap.dll, where they sit together in
one table, and the TLS one was confirmed end to end by injecting a secret with
editcap and parsing the result.
"""

from __future__ import annotations

import struct
from typing import BinaryIO

# Block types.
BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_ISB = 0x00000005
BLOCK_EPB = 0x00000006
BLOCK_DSB = 0x0000000A

BYTE_ORDER_MAGIC = 0x1A2B3C4D
VERSION_MAJOR = 1
VERSION_MINOR = 0
#: Written in the section header when the section length is not known ahead of
#: time, which for a live capture it never is.
SECTION_LENGTH_UNKNOWN = 0xFFFFFFFFFFFFFFFF

# Option codes.
OPT_ENDOFOPT = 0
OPT_COMMENT = 1
SHB_HARDWARE = 2
SHB_OS = 3
SHB_USERAPPL = 4
IF_NAME = 2
IF_DESCRIPTION = 3
IF_TSRESOL = 9
IF_FILTER = 11
ISB_STARTTIME = 2
ISB_ENDTIME = 3
ISB_IFRECV = 4
ISB_IFDROP = 5

#: Timestamps are written in microseconds since the Unix epoch. The board's own
#: resolution is about 0.5 us, measured, so microseconds neither invent
#: precision nor discard any.
TSRESOL_MICROSECONDS = 6

#: Decryption secret types, read from libwiretap.dll. Wireshark reads Zigbee
#: secrets from a capture file even though editcap will not inject them.
SECRET_TLS = 0x544C534B          # "TLSK"
SECRET_SSH = 0x5353484B          # "SSHK"
SECRET_WIREGUARD = 0x57474B4C    # "WGKL"
SECRET_ZIGBEE_NWK = 0x5A4E574B   # "ZNWK"
SECRET_ZIGBEE_APS = 0x5A415053   # "ZAPS"

DEFAULT_SNAPLEN = 262144


def _pad(value: bytes) -> bytes:
    """pcapng pads every variable-length item to a four-byte boundary."""
    remainder = len(value) % 4
    return value if remainder == 0 else value + bytes(4 - remainder)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + _pad(value)


def _text_option(code: int, text: str | None) -> bytes:
    if not text:
        return b""
    return _option(code, text.encode("utf-8"))


def _block(block_type: int, body: bytes) -> bytes:
    """Wraps a body in the block header and both length fields."""
    total = 12 + len(body)          # 4 type + 4 length + body + 4 length
    return (struct.pack("<II", block_type, total) + body
            + struct.pack("<I", total))


class PcapngWriter:
    """Writes a pcapng stream. Flushes per packet so live capture updates.

    One interface per file, which is all a single-radio sniffer can produce.
    """

    def __init__(
        self,
        stream: BinaryIO,
        linktype: int,
        snaplen: int = DEFAULT_SNAPLEN,
        *,
        hardware: str | None = None,
        os_name: str | None = None,
        application: str | None = None,
        interface_name: str | None = None,
        interface_description: str | None = None,
        capture_filter: str | None = None,
        comment: str | None = None,
    ) -> None:
        self._stream = stream
        self._snaplen = snaplen
        self._packets = 0

        section = struct.pack("<IHHQ", BYTE_ORDER_MAGIC, VERSION_MAJOR,
                              VERSION_MINOR, SECTION_LENGTH_UNKNOWN)
        options = (_text_option(OPT_COMMENT, comment)
                   + _text_option(SHB_HARDWARE, hardware)
                   + _text_option(SHB_OS, os_name)
                   + _text_option(SHB_USERAPPL, application))
        if options:
            options += _option(OPT_ENDOFOPT, b"")
        self._stream.write(_block(BLOCK_SHB, section + options))

        interface = struct.pack("<HHI", linktype, 0, snaplen)
        opts = (_text_option(IF_NAME, interface_name)
                + _text_option(IF_DESCRIPTION, interface_description)
                + _option(IF_TSRESOL, bytes([TSRESOL_MICROSECONDS])))
        if capture_filter:
            # An if_filter value is a one-byte kind followed by the filter
            # itself; 0 means a libpcap-syntax string.
            opts += _option(IF_FILTER,
                            bytes([0]) + capture_filter.encode("utf-8"))
        opts += _option(OPT_ENDOFOPT, b"")
        self._stream.write(_block(BLOCK_IDB, interface + opts))

    @staticmethod
    def _timestamp(timestamp_s: float) -> tuple[int, int]:
        """Splits a Unix time into the two 32-bit halves pcapng stores."""
        microseconds = int(round(timestamp_s * 1_000_000))
        if microseconds < 0:
            microseconds = 0
        return (microseconds >> 32) & 0xFFFFFFFF, microseconds & 0xFFFFFFFF

    def write_packet(
        self,
        data: bytes,
        timestamp_s: float,
        original_length: int | None = None,
    ) -> None:
        """Append one packet.

        `original_length` records the on-air size when `data` has been
        truncated by a snapshot length, so a sliced capture is visibly sliced
        rather than silently short.
        """
        stored = data[: self._snaplen]
        orig = original_length if original_length is not None else len(data)
        # An original shorter than what is stored is malformed, and readers
        # disagree on what to do with it, so clamp rather than emit it.
        orig = max(orig, len(stored))
        high, low = self._timestamp(timestamp_s)
        body = (struct.pack("<IIIII", 0, high, low, len(stored), orig)
                + _pad(stored))
        self._stream.write(_block(BLOCK_EPB, body))
        self._packets += 1

    def write_secret(self, secret_type: int, secret: bytes) -> None:
        """Embeds a decryption key in the capture.

        Written before the packets it applies to, which is what a live reader
        needs: Wireshark applies a secret to frames it has yet to dissect, not
        retrospectively to ones already on screen.
        """
        body = struct.pack("<II", secret_type, len(secret)) + _pad(secret)
        self._stream.write(_block(BLOCK_DSB, body))

    def write_statistics(
        self,
        *,
        received: int | None = None,
        dropped: int | None = None,
        start_time_s: float | None = None,
        end_time_s: float | None = None,
    ) -> None:
        """Records what the interface saw and what it lost.

        `dropped` is the board's own count of frames it could not deliver, so
        the file itself answers whether the capture is complete. A capture
        without such a record cannot later be told apart from a quiet channel.
        """
        high, low = self._timestamp(end_time_s or 0.0)
        body = struct.pack("<III", 0, high, low)
        options = b""
        if start_time_s is not None:
            hi, lo = self._timestamp(start_time_s)
            options += _option(ISB_STARTTIME, struct.pack("<II", hi, lo))
        if end_time_s is not None:
            hi, lo = self._timestamp(end_time_s)
            options += _option(ISB_ENDTIME, struct.pack("<II", hi, lo))
        if received is not None:
            options += _option(ISB_IFRECV, struct.pack("<Q", received))
        if dropped is not None:
            options += _option(ISB_IFDROP, struct.pack("<Q", dropped))
        options += _option(OPT_ENDOFOPT, b"")
        self._stream.write(_block(BLOCK_ISB, body + options))

    @property
    def packets_written(self) -> int:
        return self._packets

    def flush(self) -> None:
        self._stream.flush()
