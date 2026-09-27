import pytest

from esp32c6_sniffer.framing import (
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    FrameError,
    FrameType,
    crc16_ccitt_false,
    decode_frame,
    encode_frame,
)


def test_crc_matches_published_check_value():
    # CRC-16/CCITT-FALSE check value, from the CRC catalogue.
    assert crc16_ccitt_false(b"123456789") == 0x29B1


def test_crc_of_empty_input_is_init_value():
    assert crc16_ccitt_false(b"") == 0xFFFF


def _bitwise_crc(data: bytes, crc: int = 0xFFFF) -> int:
    """The polynomial loop the C firmware runs, as the reference."""
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def test_crc_matches_the_firmwares_loop_on_random_headers():
    import random
    rng = random.Random(1)
    for _ in range(5000):
        data = bytes(rng.getrandbits(8) for _ in range(rng.randrange(0, 12)))
        seed = rng.getrandbits(16)
        assert crc16_ccitt_false(data, seed) == _bitwise_crc(data, seed)


def test_crc_is_fast_enough_for_the_hot_path():
    """Half the per-frame parse cost was this function in pure Python: 4.8 us
    of 6.5 us, measured. The stdlib's C version gives the same answers."""
    import timeit
    # The best of several runs, so a busy machine does not fail it: one run
    # read 1.05 us. About 0.07 us here; pure Python is 4.6, twice the limit.
    per_call = min(timeit.repeat(
        lambda: crc16_ccitt_false(b"\xc6\x5a\x01\x00\x07\x00\x10\x00"),
        number=2000, repeat=5)) / 2000
    assert per_call < 2e-6, f"{per_call * 1e6:.2f} us per 8-byte header"


def test_encoded_header_is_ten_bytes():
    frame = encode_frame(FrameType.HEARTBEAT, seq=0, payload=b"")
    assert len(frame) == HEADER_LEN


def test_encoded_frame_starts_with_magic():
    frame = encode_frame(FrameType.PACKET, seq=1, payload=b"xy")
    assert int.from_bytes(frame[0:2], "little") == MAGIC


def test_round_trip_preserves_all_fields():
    payload = bytes(range(200))
    frame = encode_frame(FrameType.PACKET, seq=1234, payload=payload, flags=0)
    decoded = decode_frame(frame)
    assert decoded.ftype is FrameType.PACKET
    assert decoded.seq == 1234
    assert decoded.payload == payload
    assert decoded.flags == 0


def test_sequence_number_wraps_at_16_bits():
    frame = encode_frame(FrameType.PACKET, seq=65536 + 7, payload=b"")
    assert decode_frame(frame).seq == 7


def test_payload_containing_newline_bytes_survives_intact():
    # Guards the stdio CRLF-translation corruption the spec warns about.
    payload = b"\x0a\x0d\x0a\x0a\x00\xff\x0a"
    frame = encode_frame(FrameType.PACKET, seq=0, payload=payload)
    assert decode_frame(frame).payload == payload


def test_oversized_payload_is_rejected():
    with pytest.raises(FrameError):
        encode_frame(FrameType.PACKET, seq=0, payload=b"\x00" * (MAX_PAYLOAD + 1))


def test_corrupted_header_is_rejected():
    frame = bytearray(encode_frame(FrameType.PACKET, seq=5, payload=b"abc"))
    frame[4] ^= 0xFF  # flip a bit in the sequence number
    with pytest.raises(FrameError):
        decode_frame(bytes(frame))


def test_bad_magic_is_rejected():
    frame = bytearray(encode_frame(FrameType.PACKET, seq=5, payload=b"abc"))
    frame[0] ^= 0xFF
    with pytest.raises(FrameError):
        decode_frame(bytes(frame))


def test_truncated_frame_is_rejected():
    frame = encode_frame(FrameType.PACKET, seq=5, payload=b"abcdef")
    with pytest.raises(FrameError):
        decode_frame(frame[:-2])
