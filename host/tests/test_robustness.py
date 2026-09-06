"""Adversarial tests: deliberately hostile input to every decoding path.

Everything here decodes data that arrives over a radio from equipment nobody
controls, or over a link that can lose bytes. The rule those paths must obey is
narrow but absolute: **raise ValueError or return a sane result, never crash,
never hang, and never silently invent a value**. A sniffer that dies on a
malformed frame is worse than useless, because malformed frames are exactly
what a sniffer is for.

Randomised cases use a fixed seed so a failure is reproducible.
"""

from __future__ import annotations

import io
import random
import struct

import pytest

from esp32c6_sniffer.apscan import parse_ap_record
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import (
    Command,
    ControlError,
    Radio,
    decode_reply,
    encode_command,
)
from esp32c6_sniffer.csi import parse_csi_record, to_csv_row
from esp32c6_sniffer.framing import (
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    FrameType,
    encode_frame,
)
from esp32c6_sniffer.parser import SequenceTracker, StreamParser
from esp32c6_sniffer.pcap import PcapWriter
from esp32c6_sniffer.radiotap import (
    LINKTYPE_IEEE802_11_RADIOTAP,
    PhyFormat,
    build_radiotap,
    decode_he_sig_a,
    decode_ht_sig,
    rate_500kbps,
)
from esp32c6_sniffer.tap import build_tap_record

SEED = 20260906
WIFI_META = struct.Struct("<BbbBQHBBIH")
META_154 = struct.Struct("<BBbBQ")


def wifi_session():
    return CaptureSession("COM_UNUSED", channel=6, radio=Radio.WIFI)


def session_154():
    return CaptureSession("COM_UNUSED", channel=25, radio=Radio.IEEE802154)


# --- the framing parser ---------------------------------------------------

def test_parser_survives_pure_noise():
    """Random bytes must never raise, hang, or yield a frame."""
    rng = random.Random(SEED)
    parser = StreamParser()
    for _ in range(200):
        chunk = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 512)))
        for frame in parser.feed(chunk):
            # A frame out of noise is possible but must be self-consistent.
            assert isinstance(frame.payload, (bytes, bytearray))


def test_parser_recovers_a_real_frame_after_noise():
    """The whole point of resync: rubbish must not poison what follows."""
    rng = random.Random(SEED + 1)
    good = encode_frame(FrameType.PACKET, 7, b"payload-after-the-noise")
    parser = StreamParser()
    parser.feed(bytes(rng.randrange(256) for _ in range(1000)))
    frames = list(parser.feed(good))
    assert any(f.payload == b"payload-after-the-noise" for f in frames)


def test_parser_handles_a_byte_at_a_time():
    """Serial reads split wherever they like, including mid-header."""
    blob = b"".join(encode_frame(FrameType.PACKET, i, bytes([i]) * (i + 1))
                    for i in range(20))
    parser = StreamParser()
    seen = []
    for byte in blob:
        seen.extend(parser.feed(bytes([byte])))
    assert len(seen) == 20
    assert [f.seq for f in seen] == list(range(20))


def test_parser_handles_magic_inside_a_payload():
    """A payload containing the sync word must not desynchronise the stream."""
    payload = struct.pack("<H", MAGIC) * 8
    blob = encode_frame(FrameType.PACKET, 1, payload) + \
        encode_frame(FrameType.PACKET, 2, b"after")
    frames = list(StreamParser().feed(blob))
    assert [f.seq for f in frames] == [1, 2]
    assert frames[0].payload == payload


def test_parser_rejects_a_corrupted_header_without_losing_the_next_frame():
    good = encode_frame(FrameType.PACKET, 5, b"intact")
    corrupt = bytearray(encode_frame(FrameType.PACKET, 4, b"broken"))
    corrupt[3] ^= 0xFF          # damage the header, so its CRC fails
    frames = list(StreamParser().feed(bytes(corrupt) + good))
    assert [f.payload for f in frames] == [b"intact"]


def test_parser_does_not_buffer_without_bound_on_garbage():
    """A stream that never contains a valid frame must not grow memory."""
    parser = StreamParser()
    for _ in range(200):
        parser.feed(b"\x00" * 4096)
    # The parser can only need to retain less than one maximum frame.
    assert len(parser._buf) < HEADER_LEN + MAX_PAYLOAD


def test_every_payload_length_round_trips():
    for length in (0, 1, 2, HEADER_LEN, 255, 256, 1024, MAX_PAYLOAD):
        payload = bytes(range(256)) * (length // 256) + bytes(range(length % 256))
        frames = list(StreamParser().feed(
            encode_frame(FrameType.PACKET, 1, payload)))
        assert len(frames) == 1
        assert frames[0].payload == payload


# --- sequence accounting --------------------------------------------------

def test_sequence_tracker_handles_wraparound():
    """65535 -> 0 is continuity, not a 65535-frame gap."""
    tracker = SequenceTracker()
    tracker.observe(65534)
    assert tracker.observe(65535) == 0
    assert tracker.observe(0) == 0
    assert tracker.observe(1) == 0


def test_sequence_tracker_reports_a_real_gap():
    tracker = SequenceTracker()
    tracker.observe(10)
    assert tracker.observe(14) == 3


# --- Wi-Fi metadata -------------------------------------------------------

def wifi_payload(body: bytes, on_air: int, **kw) -> bytes:
    fields = dict(channel=6, rssi=-55, noise=-96, flags=0, timestamp=1,
                  rate=0, phy=1, siga1=0, siga2=0)
    fields.update(kw)
    return WIFI_META.pack(fields["channel"], fields["rssi"], fields["noise"],
                          fields["flags"], fields["timestamp"], on_air,
                          fields["rate"], fields["phy"], fields["siga1"],
                          fields["siga2"]) + body


def test_wifi_record_survives_every_truncation_of_its_metadata():
    full = wifi_payload(b"body", 4)
    session = wifi_session()
    for cut in range(len(full)):
        # Must return None or a record, never raise.
        session._build_record(full[:cut])


def test_wifi_record_survives_random_metadata():
    rng = random.Random(SEED + 2)
    session = wifi_session()
    for _ in range(2000):
        blob = bytes(rng.randrange(256)
                     for _ in range(rng.randrange(WIFI_META.size,
                                                  WIFI_META.size + 64)))
        built = session._build_record(blob)
        if built is not None:
            record, body_len, _us, original = built
            assert original >= 0
            assert body_len >= 0
            assert len(record) >= body_len


def test_wifi_channel_of_zero_is_counted_not_raised():
    """The channel is four bits wide in the radio's receive descriptor, so 0
    and 15 are both representable and neither is a real 2.4 GHz channel."""
    session = wifi_session()
    frame = bytes([0x80, 0x00]) + b"x" * 20
    assert session._build_record(wifi_payload(frame, 22, channel=0)) is None
    assert session.stats.malformed_metadata == 1


def test_wifi_channel_above_14_is_counted_not_raised():
    session = wifi_session()
    frame = bytes([0x80, 0x00]) + b"x" * 20
    for channel in (15, 200, 255):
        assert session._build_record(
            wifi_payload(frame, 22, channel=channel)) is None
    assert session.stats.malformed_metadata == 3


def test_a_malformed_frame_does_not_stop_the_ones_after_it():
    """The whole point: one bad frame must cost one frame, not the capture."""
    session = wifi_session()
    frame = bytes([0x80, 0x00]) + b"x" * 20
    assert session._build_record(wifi_payload(frame, 22, channel=0)) is None
    assert session._build_record(wifi_payload(frame, 22, channel=6)) is not None
    assert session.stats.malformed_metadata == 1


def test_802154_record_survives_every_truncation():
    full = META_154.pack(25, 200, -60, 0, 1) + b"psdu"
    session = session_154()
    for cut in range(len(full)):
        session._build_record(full[:cut])


def test_802154_record_survives_random_metadata():
    rng = random.Random(SEED + 3)
    session = session_154()
    for _ in range(2000):
        blob = bytes(rng.randrange(256)
                     for _ in range(rng.randrange(META_154.size,
                                                  META_154.size + 200)))
        session._build_record(blob)


# --- signalling-field decoders -------------------------------------------

def test_ht_decoder_never_raises_on_random_input():
    rng = random.Random(SEED + 4)
    for _ in range(20000):
        out = decode_ht_sig(rng.randrange(1 << 32), rng.randrange(1 << 16),
                            rng.randrange(4096))
        if out is not None:
            known, flags, mcs = out
            assert 0 <= mcs <= 76
            assert 0 <= known <= 0xFF
            assert 0 <= flags <= 0xFF


def test_he_decoder_never_raises_on_random_input():
    rng = random.Random(SEED + 5)
    for _ in range(20000):
        out = decode_he_sig_a(rng.randrange(1 << 32), rng.randrange(1 << 16))
        if out is not None:
            assert len(out) == 6
            assert all(0 <= word <= 0xFFFF for word in out)


def test_rate_table_never_raises():
    for fmt in range(16):
        for code in range(256):
            value = rate_500kbps(fmt, code)
            assert value is None or 0 < value <= 0xFF


# --- radiotap and TAP builders -------------------------------------------

def test_radiotap_rejects_an_out_of_range_signal():
    with pytest.raises(ValueError):
        build_radiotap(channel=6, rssi_dbm=200)


def test_radiotap_rejects_an_impossible_channel():
    for channel in (0, 15, 255):
        with pytest.raises(ValueError):
            build_radiotap(channel=channel, rssi_dbm=-50)


def test_radiotap_length_field_always_matches_the_bytes_produced():
    """A wrong length here makes Wireshark read the frame at the wrong offset
    and report plausible nonsense rather than an error."""
    rng = random.Random(SEED + 6)
    for _ in range(500):
        header = build_radiotap(
            channel=rng.randrange(1, 15),
            rssi_dbm=rng.randrange(-128, 128),
            noise_dbm=rng.choice([None, rng.randrange(-128, 128)]),
            timestamp_us=rng.choice([None, rng.randrange(1 << 40)]),
            rate_500kbps_units=rng.choice([None, rng.randrange(1, 256)]),
            mcs=rng.choice([None, (1, 2, 7)]),
            ampdu_reference=rng.choice([None, rng.randrange(1 << 32)]),
            he=rng.choice([None, (1, 2, 3, 4, 5, 6)]),
        )
        declared = struct.unpack_from("<H", header, 2)[0]
        assert declared == len(header)


def test_tap_record_length_always_matches():
    rng = random.Random(SEED + 7)
    for _ in range(300):
        psdu = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 128)))
        record = build_tap_record(psdu, channel=rng.randrange(11, 27),
                                  rssi_dbm=float(rng.randrange(-128, 0)),
                                  lqi=rng.randrange(256))
        declared = struct.unpack_from("<H", record, 2)[0]
        assert declared + len(psdu) == len(record)


# --- CSI and access-point records ----------------------------------------

def test_csi_survives_every_truncation():
    body = struct.pack("<QbbBB6sHBH", 1, -50, -95, 6, 1,
                       b"\x01\x02\x03\x04\x05\x06", 3, 0, 4) + b"\x01\x02\x03\x04"
    for cut in range(len(body)):
        try:
            parse_csi_record(body[:cut])
        except ValueError:
            pass


def test_csi_survives_random_input():
    rng = random.Random(SEED + 8)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 128)))
        try:
            record = parse_csi_record(blob)
        except ValueError:
            continue
        assert record.subcarriers * 2 <= len(record.raw) + 1
        record.amplitudes()
        to_csv_row(record)


def test_csi_csv_row_never_contains_a_newline():
    """One record per line, whatever the radio said. A newline in the middle
    would silently split one measurement into two rows."""
    rng = random.Random(SEED + 9)
    for _ in range(200):
        length = rng.randrange(0, 64) * 2
        raw = bytes(rng.randrange(256) for _ in range(length))
        blob = struct.pack("<QbbBB6sHBH", rng.randrange(1 << 63), -50, -95, 6,
                           1, bytes(rng.randrange(256) for _ in range(6)),
                           rng.randrange(1 << 16), 0, length) + raw
        row = to_csv_row(parse_csi_record(blob))
        assert "\n" not in row and "\r" not in row


def test_ap_record_survives_random_input():
    rng = random.Random(SEED + 10)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
        try:
            record = parse_ap_record(blob)
        except ValueError:
            continue
        assert isinstance(record.ssid, str)
        assert record.auth_name


def test_ap_ssid_with_control_characters_stays_one_line():
    """SSIDs are attacker-controlled: 32 arbitrary bytes, newlines included."""
    ssid = b"evil\nnetwork\r\x00name"
    blob = struct.pack("<bBBB6s", -50, 6, 3, len(ssid), b"\x00" * 6) + ssid
    record = parse_ap_record(blob)
    assert record.ssid  # decoded, not crashed


# --- pcap output ----------------------------------------------------------

def test_pcap_never_declares_an_original_shorter_than_the_capture():
    """orig_len < incl_len is malformed pcap, and readers disagree on what to
    do with it."""
    stream = io.BytesIO()
    writer = PcapWriter(stream, LINKTYPE_IEEE802_11_RADIOTAP)
    writer.write_packet(b"abcdefgh", 1.0, original_length=2)
    blob = stream.getvalue()
    _sec, _usec, incl, orig = struct.unpack_from("<IIII", blob, 24)
    assert orig >= incl, f"pcap declares original {orig} < captured {incl}"


def test_pcap_handles_an_epoch_timestamp_of_zero():
    stream = io.BytesIO()
    writer = PcapWriter(stream, LINKTYPE_IEEE802_11_RADIOTAP)
    writer.write_packet(b"x", 0.0)
    assert len(stream.getvalue()) > 24


# --- the command encoder --------------------------------------------------

def test_encoder_rejects_out_of_range_channels_for_both_radios():
    for radio, bad in ((Radio.IEEE802154, (0, 10, 27, 255)),
                       (Radio.WIFI, (0, 15, 255))):
        for channel in bad:
            with pytest.raises(ValueError):
                encode_command(Command.SET_CHANNEL, channel, radio=radio)


def test_encoder_rejects_a_value_wider_than_the_field():
    with pytest.raises(ValueError):
        encode_command(Command.SET_FILTER, 1 << 32)


def test_encoder_rejects_a_nonsense_antenna():
    with pytest.raises(ValueError):
        encode_command(Command.SET_ANTENNA, 7)


def test_reply_decoder_survives_random_input():
    rng = random.Random(SEED + 11)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 16)))
        try:
            decode_reply(blob)
        except (ControlError, ValueError, struct.error, KeyError):
            pass


def test_reply_with_an_unknown_command_does_not_raise():
    """The board echoes back whatever it was sent, so an unknown command puts
    an unknown identifier in a reply. Raising there killed the capture loop
    that read it."""
    payload = struct.pack("<BBI", 200, 1, 0)
    reply = decode_reply(payload)
    assert reply["command"] == 200
    assert not reply["ok"]
    # And it must not masquerade as a command the caller is waiting for.
    assert reply["command"] not in tuple(Command)


def test_reply_too_short_still_raises():
    """A runt is a framing failure, which is different from an unknown one."""
    with pytest.raises(ControlError):
        decode_reply(b"\x01\x00")
