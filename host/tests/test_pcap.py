import io
import struct

from esp32c6_sniffer.pcap import PCAP_MAGIC_MICROSECONDS, PcapWriter


def _header(buf: bytes):
    return struct.unpack("<IHHiIII", buf[:24])


def test_header_declares_the_requested_linktype():
    buf = io.BytesIO()
    PcapWriter(buf, linktype=283)
    magic, vmaj, vmin, tz, sig, snap, link = _header(buf.getvalue())
    assert magic == PCAP_MAGIC_MICROSECONDS
    assert (vmaj, vmin) == (2, 4)
    assert tz == 0
    assert sig == 0
    assert link == 283


def test_header_is_exactly_24_bytes():
    buf = io.BytesIO()
    PcapWriter(buf, linktype=283)
    assert len(buf.getvalue()) == 24


def test_packet_record_length_matches_payload():
    buf = io.BytesIO()
    w = PcapWriter(buf, linktype=283)
    w.write_packet(b"\x01\x02\x03", timestamp_s=1_700_000_000.5)
    rec = buf.getvalue()[24:]
    ts_sec, ts_usec, incl, orig = struct.unpack("<IIII", rec[:16])
    assert ts_sec == 1_700_000_000
    assert ts_usec == 500_000
    assert incl == orig == 3
    assert rec[16:] == b"\x01\x02\x03"


def test_snaplen_truncates_and_records_original_length():
    """A truncated capture must look truncated, not merely short."""
    buf = io.BytesIO()
    w = PcapWriter(buf, linktype=283, snaplen=4)
    w.write_packet(b"\xaa" * 20, timestamp_s=1.0)
    _, _, incl, orig = struct.unpack("<IIII", buf.getvalue()[24:40])
    assert incl == 4
    assert orig == 20


def test_explicit_original_length_is_preserved():
    buf = io.BytesIO()
    w = PcapWriter(buf, linktype=283)
    w.write_packet(b"\x00" * 10, timestamp_s=1.0, original_length=1500)
    _, _, incl, orig = struct.unpack("<IIII", buf.getvalue()[24:40])
    assert incl == 10
    assert orig == 1500


def test_microsecond_rounding_does_not_produce_an_invalid_record():
    """0.9999996 must not round to 1000000 microseconds."""
    buf = io.BytesIO()
    w = PcapWriter(buf, linktype=283)
    w.write_packet(b"\x00", timestamp_s=10.9999996)
    ts_sec, ts_usec, _, _ = struct.unpack("<IIII", buf.getvalue()[24:40])
    assert ts_usec < 1_000_000
    assert ts_sec == 11
    assert ts_usec == 0


def test_two_packets_are_written_back_to_back():
    buf = io.BytesIO()
    w = PcapWriter(buf, linktype=283)
    w.write_packet(b"\x01", timestamp_s=1.0)
    w.write_packet(b"\x02\x03", timestamp_s=2.0)
    body = buf.getvalue()[24:]
    assert len(body) == 16 + 1 + 16 + 2
    assert body[16:17] == b"\x01"
    assert body[33:35] == b"\x02\x03"
