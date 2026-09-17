"""PACKET_BATCH and LINK: the layouts that let the nRF54L15's UART keep up.

The point of every test here is the same: a batch must decode into exactly the
packets that went in, with exactly their timestamps, and a payload that cannot
be decoded whole must be refused rather than half-believed.
"""

import struct

import pytest

from esp32c6_sniffer import batch
from esp32c6_sniffer.batch import (BatchEntry, BatchError, LinkStatus,
                                   decode_link, decode_packet_batch,
                                   encode_link, encode_packet_batch,
    BleBatchEntry, encode_ble_batch, decode_ble_batch)
from esp32c6_sniffer.capture import _META, META_LEN


def entries_for(*timestamps):
    return [BatchEntry(ts, lqi=200 - i, rssi_dbm=-60 - i,
                       psdu=bytes([i]) * (5 + i))
            for i, ts in enumerate(timestamps)]


def test_a_batch_round_trips_exactly():
    original = entries_for(1_000_000, 1_000_450, 1_003_000)
    channel, decoded = decode_packet_batch(encode_packet_batch(25, original))
    assert channel == 25
    assert decoded == original


def test_timestamps_are_absolute_on_the_way_out():
    """The delta coding must never leak: the caller sees the board's clock."""
    _, decoded = decode_packet_batch(
        encode_packet_batch(11, entries_for(5_000_000, 5_000_100, 5_065_535)))
    assert [e.timestamp_us for e in decoded] == [5_000_000, 5_000_100, 5_065_535]


def test_the_first_delta_is_zero_and_the_header_carries_the_base():
    payload = encode_packet_batch(15, entries_for(777_777))
    base, channel, count = batch.BATCH_HEADER.unpack_from(payload)
    dt, *_ = batch.BATCH_ENTRY.unpack_from(payload, batch.BATCH_HEADER_LEN)
    assert (base, channel, count, dt) == (777_777, 15, 1, 0)


def test_per_packet_overhead_is_what_the_design_claims():
    """22 bytes per packet as PACKET frames; about 5.6 batched. The number the
    whole feature rests on, so it is asserted rather than described."""
    psdus = [bytes(5)] * 32                      # 32 acknowledgements
    entries = [BatchEntry(1000 + i, 0, -70, p) for i, p in enumerate(psdus)]
    payload = encode_packet_batch(25, entries)
    payload_bytes = sum(len(p) for p in psdus)
    overhead_per_packet = (len(payload) - payload_bytes + 10) / 32   # +10: frame header
    assert overhead_per_packet < 6
    # 32 entries x 5 bytes, plus the 10-byte batch header, plus the 10-byte
    # frame header, over 32 packets. Against 22 bytes per packet unbatched.
    assert overhead_per_packet == pytest.approx(5.625)


def test_a_batch_entry_becomes_a_packet_payload_the_existing_decoder_accepts():
    """The host expands each entry into a synthetic PACKET payload and feeds
    it through _build_record unchanged. So the two layouts must agree field
    for field, or a batched capture would decode differently from a plain one."""
    entry = BatchEntry(timestamp_us=123_456_789, lqi=88, rssi_dbm=-77,
                       psdu=b"\x41\x88\x1e\x07\xf2")
    channel, (decoded,) = decode_packet_batch(encode_packet_batch(20, [entry]))
    synthetic = _META.pack(channel, decoded.lqi, decoded.rssi_dbm, 0,
                           decoded.timestamp_us) + decoded.psdu
    ch, lqi, rssi, flags, ts = _META.unpack_from(synthetic)
    assert (ch, lqi, rssi, flags, ts) == (20, 88, -77, 0, 123_456_789)
    assert synthetic[META_LEN:] == entry.psdu


@pytest.mark.parametrize("count", [0, 33])
def test_count_bounds_are_enforced(count):
    with pytest.raises(BatchError):
        encode_packet_batch(25, entries_for(*range(count)))


def test_a_delta_too_wide_for_sixteen_bits_is_refused_not_truncated():
    """The firmware closes a batch at this boundary. An encoder that silently
    wrapped would produce a payload no firmware would, with a timestamp
    65.5 ms wrong and nothing to say so."""
    with pytest.raises(BatchError):
        encode_packet_batch(25, entries_for(0, batch.MAX_DT_US + 1))


def test_timestamps_going_backwards_are_refused():
    with pytest.raises(BatchError):
        encode_packet_batch(25, entries_for(2000, 1000))


def test_an_oversized_psdu_is_refused():
    with pytest.raises(BatchError):
        encode_packet_batch(25, [BatchEntry(0, 0, 0, bytes(batch.MAX_PSDU + 1))])


@pytest.mark.parametrize("cut", [3, batch.BATCH_HEADER_LEN + 2, -1])
def test_a_truncated_batch_raises_rather_than_yielding_a_partial_one(cut):
    """Half a batch believed whole is several frames with confident wrong
    timestamps. One frame reported lost is the honest alternative."""
    payload = encode_packet_batch(25, entries_for(10, 20, 30))
    with pytest.raises(BatchError):
        decode_packet_batch(payload[:cut])


def test_trailing_bytes_are_an_error():
    payload = encode_packet_batch(25, entries_for(10)) + b"\x00"
    with pytest.raises(BatchError):
        decode_packet_batch(payload)


def test_a_count_of_zero_on_the_wire_is_refused():
    payload = bytearray(encode_packet_batch(25, entries_for(10)))
    struct.pack_into("<B", payload, 9, 0)
    with pytest.raises(BatchError):
        decode_packet_batch(bytes(payload))


def test_link_status_round_trips():
    assert decode_link(encode_link(48_000, 131_072, 196_608)) == LinkStatus(
        queued_bytes=48_000, high_water=131_072, capacity=196_608)


def test_link_status_is_twelve_bytes():
    """Occupancy only. Drops travel in STATS, where they already reach the
    pcapng statistics; a fourth field here would double-count them."""
    assert batch.LINK_LEN == 12
    assert len(encode_link(0, 0, 0)) == 12


def test_a_link_payload_of_the_wrong_length_is_refused():
    with pytest.raises(BatchError):
        decode_link(b"\x00" * 11)


# ---------------------------------------------------------------- BLE batches

def ble_entry(ts, payload=b"\x04\x3e\x2b" + b"z" * 42, flags=0, orig=None):
    hci = bytes(payload)
    return BleBatchEntry(ts, orig if orig is not None else len(hci), flags, hci)


def test_a_ble_batch_round_trips_exactly():
    entries = [ble_entry(1_000_000), ble_entry(1_000_450), ble_entry(1_003_000)]
    back = decode_ble_batch(encode_ble_batch(entries))
    assert [(e.timestamp_us, e.orig_len, e.flags, e.hci) for e in back] == [
        (e.timestamp_us, e.orig_len, e.flags, e.hci) for e in entries
    ]


def test_ble_timestamps_are_absolute_on_the_way_out():
    """The delta coding is an encoding detail and must never leak."""
    entries = [ble_entry(5_000_000), ble_entry(5_000_017)]
    back = decode_ble_batch(encode_ble_batch(entries))
    assert [e.timestamp_us for e in back] == [5_000_000, 5_000_017]


def test_a_ble_batch_entry_becomes_the_payload_the_existing_decoder_accepts():
    """The whole point: after expansion a batched capture is not
    distinguishable from an unbatched one, so nothing downstream can decode
    the two differently."""
    from esp32c6_sniffer.ble import build_payload, build_ble_record

    entry = ble_entry(7_654_321)
    payload = build_payload(entry.timestamp_us, entry.orig_len,
                            entry.flags, entry.hci)
    record, hci_len, timestamp_us = build_ble_record(payload)
    assert timestamp_us == 7_654_321
    assert hci_len == len(entry.hci)
    assert record.endswith(entry.hci)


def test_ble_per_packet_overhead_is_what_the_design_claims():
    """A full batch must beat the 22 bytes an unbatched BLE packet costs --
    10 of frame header and 12 of metadata -- or it is not worth having."""
    hci = b"\x04\x3e\x2b" + b"z" * 42
    entries = [ble_entry(1_000_000 + i * 1000, hci) for i in range(32)]
    encoded = encode_ble_batch(entries)
    overhead = (len(encoded) - 32 * len(hci) + 10) / 32   # +10: frame header
    assert overhead < 22, overhead
    # 32 entries x 7 bytes, plus the 9-byte batch header and the 10-byte frame
    # header, over 32 packets. The entry grew from 6 to 7 when the length
    # field had to widen to carry a full-size HCI event.
    assert overhead == pytest.approx(7.6, abs=0.1), overhead


def test_a_single_ble_entry_costs_more_than_not_batching():
    """Which is why both firmwares send a batch of one as a plain PACKET."""
    hci = b"\x04\x3e\x2b" + b"z" * 42
    encoded = encode_ble_batch([ble_entry(1_000_000, hci)])
    assert len(encoded) - len(hci) + 10 > 22


@pytest.mark.parametrize("count", [0, 33])
def test_ble_count_bounds_are_enforced(count):
    entries = [ble_entry(1_000_000 + i * 1000) for i in range(count)]
    with pytest.raises(BatchError):
        encode_ble_batch(entries)


def test_a_ble_delta_too_wide_for_sixteen_bits_is_refused_not_truncated():
    entries = [ble_entry(1_000_000), ble_entry(1_000_000 + 0x10000)]
    with pytest.raises(BatchError):
        encode_ble_batch(entries)


def test_ble_timestamps_going_backwards_are_refused():
    with pytest.raises(BatchError):
        encode_ble_batch([ble_entry(1_000_000), ble_entry(999_999)])


def test_an_orig_len_smaller_than_the_bytes_carried_is_refused():
    """orig_len says what was received before truncation, so it can exceed
    what is carried but never fall short of it."""
    with pytest.raises(BatchError):
        encode_ble_batch([ble_entry(1_000_000, b"\x04\x3e\x05abc", orig=2)])


def test_a_truncated_ble_batch_raises_rather_than_yielding_a_partial_one():
    encoded = encode_ble_batch([ble_entry(1_000_000), ble_entry(1_000_450)])
    with pytest.raises(BatchError):
        decode_ble_batch(encoded[:-5])


def test_ble_trailing_bytes_are_an_error():
    encoded = encode_ble_batch([ble_entry(1_000_000)])
    with pytest.raises(BatchError):
        decode_ble_batch(encoded + b"\x00")


def test_a_ble_batch_is_not_decodable_as_an_802154_batch():
    """The two layouts share a module and must not share a decoder. Reading
    one as the other is exactly the confident-wrong-number failure the frame
    types exist to prevent."""
    encoded = encode_ble_batch([ble_entry(1_000_000), ble_entry(1_000_450)])
    try:
        channel, entries = decode_packet_batch(encoded)
    except BatchError:
        return
    assert [e.psdu for e in entries] != [e.hci for e in
                                         decode_ble_batch(encoded)]


def test_an_hci_packet_longer_than_255_bytes_survives_a_batch():
    """The length field is sixteen bits for this reason. An HCI event reaches
    258 bytes -- a type byte, a two-byte header and up to 255 of parameters --
    and an eight-bit length wrapped modulo 256, so the decoder lost alignment
    part-way through a batch and reported trailing bytes. Nothing named the
    length, and every earlier test here used a short payload."""
    big = b"\x04\x3e\xff" + b"q" * 255          # 258 bytes, the true maximum
    assert len(big) == 258
    entries = [ble_entry(1_000_000, big), ble_entry(1_000_400, big)]
    back = decode_ble_batch(encode_ble_batch(entries))
    assert [len(e.hci) for e in back] == [258, 258]
    assert [e.hci for e in back] == [big, big]
