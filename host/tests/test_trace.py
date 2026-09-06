"""Decoding the board's event trace into durations.

The trace exists because the host can measure that a command took 106 ms and
cannot say which side spent it. It answered that: a STOP costs 0.3 ms on the
board, and the remaining 105 ms was the host's own serial read timeout.

Entries are recorded without a lock, so a writer racing the dump loses or
duplicates one. These tests therefore care as much about what happens to a
malformed or unmatched entry as about the happy path.
"""

import struct

from esp32c6_sniffer.trace import (
    ENTRY,
    EVENTS,
    parse_entries,
    slowest,
    spans,
)

CMD_IN, CMD_OUT = 1, 2
WIFI_STOP_IN, WIFI_STOP_OUT = 22, 23
BLE_STOP_IN, BLE_STOP_OUT = 32, 33


def entry(us, event, arg8=0, arg16=0):
    return ENTRY.pack(us, event, arg8, arg16)


def test_one_entry_decodes():
    got = parse_entries(entry(1234, CMD_IN, 4, 0))
    assert len(got) == 1
    assert (got[0].us, got[0].event, got[0].arg8) == (1234, CMD_IN, 4)
    assert got[0].name == "cmd in"


def test_a_trailing_partial_entry_is_dropped_not_raised():
    """A dump can be cut short by a full link buffer; half an entry must not
    lose the whole frame."""
    payload = entry(1, CMD_IN) + b"\x01\x02\x03"
    assert len(parse_entries(payload)) == 1


def test_an_empty_frame_yields_nothing():
    assert parse_entries(b"") == []


def test_a_span_is_the_gap_between_entry_and_exit():
    got = spans(parse_entries(entry(1000, CMD_IN, 4) + entry(4100, CMD_OUT, 4)))
    assert len(got) == 1
    assert got[0].duration_us == 3100
    assert abs(got[0].ms - 3.1) < 1e-9


def test_spans_are_matched_on_the_argument_too():
    """The BLE controller's disable and deinit share an event and differ only
    by argument. Matching on the event alone had the first exit close the
    second entry, which reports two real calls as one impossible one."""
    payload = (entry(100, BLE_STOP_IN, 2) + entry(200, BLE_STOP_OUT, 2)
               + entry(300, BLE_STOP_IN, 3) + entry(1800, BLE_STOP_OUT, 3))
    got = {s.arg8: s.duration_us for s in spans(parse_entries(payload))}
    assert got == {2: 100, 3: 1500}


def test_an_unmatched_entry_is_skipped_rather_than_guessed():
    """The ring can be dumped mid-call, or have wrapped and lost the exit.
    Inventing a duration for it would report a call that never finished as a
    fast one."""
    payload = entry(100, WIFI_STOP_IN, 1) + entry(200, CMD_OUT, 4)
    assert spans(parse_entries(payload)) == []


def test_a_wrapped_timestamp_does_not_produce_a_negative_duration():
    """The board's clock is the low 32 bits of a microsecond counter, so it
    wraps about every 71 minutes. A span across the wrap read as roughly minus
    an hour before this was handled."""
    payload = (entry(0xFFFFFF00, WIFI_STOP_IN, 1)
               + entry(0x00000100, WIFI_STOP_OUT, 1))
    got = spans(parse_entries(payload))
    assert len(got) == 1
    assert got[0].duration_us == 0x200


def test_slowest_orders_by_duration():
    payload = (entry(0, CMD_IN, 1) + entry(1000, CMD_OUT, 1)
               + entry(2000, CMD_IN, 2) + entry(9000, CMD_OUT, 2)
               + entry(10000, CMD_IN, 3) + entry(10500, CMD_OUT, 3))
    order = [s.arg8 for s in slowest(parse_entries(payload))]
    assert order == [2, 1, 3]


def test_every_span_opener_has_a_name():
    """An unnamed event prints as a bare number, which is unreadable in a
    table whose whole job is to say which call was slow."""
    from esp32c6_sniffer.trace import SPANS

    for start, end in SPANS.items():
        assert start in EVENTS, start
        assert end in EVENTS, end


def test_the_entry_layout_matches_the_firmware():
    """sn_trace_entry_t is uint32 us, uint8 event, uint8 arg8, uint16 arg16.
    Eight bytes; a mismatch here silently misreads every field after the
    first."""
    assert ENTRY.size == 8
    assert ENTRY.format in ("<IBBH", b"<IBBH")
