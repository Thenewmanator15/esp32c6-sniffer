"""The pcapng writer, checked by parsing back what it writes.

The block layout came from a file Wireshark itself wrote and the interface
statistics were compared against dumpcap's, so these tests guard a format that
was established externally rather than one invented here.
"""

import io
import struct

import pytest

from esp32c6_sniffer.pcapng import (
    BLOCK_DSB,
    BLOCK_EPB,
    BLOCK_IDB,
    BLOCK_ISB,
    BLOCK_SHB,
    BYTE_ORDER_MAGIC,
    SECRET_ZIGBEE_APS,
    SECRET_ZIGBEE_NWK,
    TSRESOL_MICROSECONDS,
    PcapngWriter,
)

LINKTYPE = 283


def blocks(data: bytes):
    """Walks the stream the way a reader does, using only the length fields."""
    out = []
    off = 0
    while off + 12 <= len(data):
        btype, blen = struct.unpack_from("<II", data, off)
        assert blen >= 12, f"block length {blen} at {off}"
        assert blen % 4 == 0, f"block length {blen} is not a multiple of four"
        assert off + blen <= len(data), "block runs past the end"
        trailer = struct.unpack_from("<I", data, off + blen - 4)[0]
        # The repeated length is what lets a reader walk backwards. If it
        # disagrees the file is unnavigable in one direction only, which is
        # exactly the kind of fault that survives a casual look.
        assert trailer == blen, f"trailing length {trailer} != {blen}"
        out.append((btype, data[off + 8:off + blen - 4]))
        off += blen
    assert off == len(data), "trailing bytes that are not a block"
    return out


def options(body: bytes, skip: int):
    """Decodes the option list that follows a block body."""
    out = {}
    pos = skip
    while pos + 4 <= len(body):
        code, length = struct.unpack_from("<HH", body, pos)
        if code == 0:
            break
        out[code] = body[pos + 4:pos + 4 + length]
        pos += 4 + (length + 3) // 4 * 4
    return out


def write(**kwargs):
    stream = io.BytesIO()
    writer = PcapngWriter(stream, LINKTYPE, **kwargs)
    return stream, writer


def test_a_bare_file_is_a_section_then_an_interface():
    stream, _ = write()
    types = [btype for btype, _ in blocks(stream.getvalue())]
    assert types == [BLOCK_SHB, BLOCK_IDB]


def test_section_header_declares_byte_order_and_version():
    stream, _ = write()
    body = blocks(stream.getvalue())[0][1]
    magic, major, minor, section_length = struct.unpack_from("<IHHQ", body, 0)
    assert magic == BYTE_ORDER_MAGIC
    assert (major, minor) == (1, 0)
    # A live capture cannot know its own length in advance, and writing a
    # wrong one is worse than declaring it unknown.
    assert section_length == 0xFFFFFFFFFFFFFFFF


def test_interface_declares_the_link_type_and_microsecond_resolution():
    stream, _ = write(snaplen=256)
    body = blocks(stream.getvalue())[1][1]
    linktype, reserved, snaplen = struct.unpack_from("<HHI", body, 0)
    assert (linktype, reserved, snaplen) == (LINKTYPE, 0, 256)
    # Without if_tsresol a reader assumes microseconds anyway, but stating it
    # keeps the file honest if the resolution ever changes.
    assert options(body, 8)[9] == bytes([TSRESOL_MICROSECONDS])


def test_metadata_reaches_the_file():
    stream, _ = write(hardware="XIAO ESP32-C6", os_name="Windows 11",
                      application="esp32c6-sniffer", interface_name="wifi",
                      interface_description="2.4 GHz, channel 6")
    shb = options(blocks(stream.getvalue())[0][1], 16)
    idb = options(blocks(stream.getvalue())[1][1], 8)
    assert shb[2] == b"XIAO ESP32-C6"
    assert shb[3] == b"Windows 11"
    assert shb[4] == b"esp32c6-sniffer"
    assert idb[2] == b"wifi"
    assert idb[3] == b"2.4 GHz, channel 6"


@pytest.mark.parametrize("length", range(1, 9))
def test_a_packet_of_any_length_keeps_the_stream_walkable(length):
    """Every variable-length item is padded to four bytes. Getting that wrong
    for odd lengths leaves a file that reads correctly until the first packet
    whose size is not a multiple of four."""
    stream, writer = write()
    writer.write_packet(bytes(range(length)), 1_700_000_000.5)
    found = blocks(stream.getvalue())
    assert [b for b, _ in found] == [BLOCK_SHB, BLOCK_IDB, BLOCK_EPB]
    body = found[2][1]
    _iface, _hi, _lo, captured, original = struct.unpack_from("<IIIII", body, 0)
    assert captured == original == length
    assert body[20:20 + length] == bytes(range(length))


def test_timestamps_are_microseconds_since_the_epoch():
    stream, writer = write()
    writer.write_packet(b"x", 1_700_000_000.123456)
    body = blocks(stream.getvalue())[2][1]
    _iface, high, low = struct.unpack_from("<III", body, 0)
    assert (high << 32) | low == 1_700_000_000_123_456


def test_a_truncated_packet_records_its_original_length():
    stream, writer = write(snaplen=4)
    writer.write_packet(b"0123456789", 1_700_000_000.0, original_length=10)
    body = blocks(stream.getvalue())[2][1]
    captured, original = struct.unpack_from("<II", body, 12)
    assert (captured, original) == (4, 10)


def test_an_original_shorter_than_the_stored_bytes_is_clamped():
    """Readers disagree on what to do with it, so the file would be subtly
    wrong rather than obviously broken."""
    stream, writer = write()
    writer.write_packet(b"0123456789", 1_700_000_000.0, original_length=2)
    body = blocks(stream.getvalue())[2][1]
    captured, original = struct.unpack_from("<II", body, 12)
    assert captured == original == 10


def test_a_secret_is_written_with_its_type_and_length():
    stream, writer = write()
    key = bytes(range(16))
    writer.write_secret(SECRET_ZIGBEE_NWK, key)
    btype, body = blocks(stream.getvalue())[2]
    assert btype == BLOCK_DSB
    secret_type, length = struct.unpack_from("<II", body, 0)
    assert secret_type == SECRET_ZIGBEE_NWK
    assert length == 16
    assert body[8:8 + length] == key


def test_the_secret_types_are_the_four_character_codes_wireshark_uses():
    """Read out of libwiretap.dll, and the TLS one confirmed end to end by
    injecting a secret with editcap and parsing the result back."""
    assert struct.pack(">I", SECRET_ZIGBEE_NWK) == b"ZNWK"
    assert struct.pack(">I", SECRET_ZIGBEE_APS) == b"ZAPS"


def test_a_secret_of_odd_length_still_leaves_the_stream_walkable():
    stream, writer = write()
    writer.write_secret(SECRET_ZIGBEE_NWK, b"abc")
    assert [b for b, _ in blocks(stream.getvalue())][-1] == BLOCK_DSB


def test_statistics_carry_the_counts_and_the_window():
    stream, writer = write()
    writer.write_statistics(received=2595, dropped=7,
                            start_time_s=1_700_000_000.0,
                            end_time_s=1_700_000_060.0)
    btype, body = blocks(stream.getvalue())[2]
    assert btype == BLOCK_ISB
    opts = options(body, 12)
    # Option codes and widths match what dumpcap writes; compared directly
    # against a file it produced.
    assert struct.unpack("<Q", opts[4])[0] == 2595      # isb_ifrecv
    assert struct.unpack("<Q", opts[5])[0] == 7         # isb_ifdrop
    high, low = struct.unpack("<II", opts[2])           # isb_starttime
    assert (high << 32) | low == 1_700_000_000_000_000
    high, low = struct.unpack("<II", opts[3])           # isb_endtime
    assert (high << 32) | low == 1_700_000_060_000_000


def test_zero_drops_are_recorded_rather_than_omitted():
    """A capture with no drop record cannot be told apart later from one that
    dropped nothing, so the zero has to be written."""
    stream, writer = write()
    writer.write_statistics(received=10, dropped=0)
    opts = options(blocks(stream.getvalue())[2][1], 12)
    assert 5 in opts and struct.unpack("<Q", opts[5])[0] == 0


def test_packets_written_counts_only_packets():
    stream, writer = write()
    writer.write_secret(SECRET_ZIGBEE_NWK, bytes(16))
    for _ in range(3):
        writer.write_packet(b"x", 1_700_000_000.0)
    writer.write_statistics(received=3)
    assert writer.packets_written == 3


def test_a_full_file_walks_end_to_end():
    stream, writer = write(hardware="XIAO ESP32-C6", interface_name="802154")
    writer.write_secret(SECRET_ZIGBEE_NWK, bytes(16))
    for i in range(5):
        writer.write_packet(bytes(i + 1), 1_700_000_000.0 + i)
    writer.write_statistics(received=5, dropped=0, start_time_s=1_700_000_000.0,
                            end_time_s=1_700_000_005.0)
    assert [b for b, _ in blocks(stream.getvalue())] == [
        BLOCK_SHB, BLOCK_IDB, BLOCK_DSB,
        BLOCK_EPB, BLOCK_EPB, BLOCK_EPB, BLOCK_EPB, BLOCK_EPB,
        BLOCK_ISB,
    ]
