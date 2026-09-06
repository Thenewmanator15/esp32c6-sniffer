"""Reading the board's event trace.

The host can measure that a command took two seconds and can say nothing about
where they went: everything between the request and the reply happens inside
driver calls on the board. The firmware records a timestamped event on entry
to and exit from each of those, and this turns the result back into durations.

Entries are eight bytes -- microsecond timestamp, event, and two arguments --
and are recorded without a lock. A writer racing the dump loses or duplicates
one entry rather than blocking, because taking a lock in an interrupt would
change the timing the trace exists to measure. So an occasional impossible
entry is expected and is not evidence of a fault.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

ENTRY = struct.Struct("<IBBH")
ENTRY_LEN = ENTRY.size

#: Must match sn_trace_event_t in firmware/main/trace.h.
EVENTS = {
    0: "none",
    1: "cmd in",
    2: "cmd out",
    10: "802.15.4 start in",
    11: "802.15.4 start out",
    12: "802.15.4 stop in",
    13: "802.15.4 stop out",
    20: "wifi start in",
    21: "wifi start out",
    22: "wifi stop in",
    23: "wifi stop out",
    24: "wifi init in",
    25: "wifi init out",
    30: "ble start in",
    31: "ble start out",
    32: "ble stop in",
    33: "ble stop out",
    40: "rx",
    41: "ring full",
    42: "tx stall",
    60: "mark",
}

#: Events that open a span, mapped to the event that closes it. A span is
#: matched on (event, arg8) so the BLE controller's disable and deinit, which
#: share an event and differ only by argument, do not close each other.
SPANS = {1: 2, 10: 11, 12: 13, 20: 21, 22: 23, 24: 25, 30: 31, 32: 33}


@dataclass(frozen=True)
class TraceEntry:
    us: int
    event: int
    arg8: int
    arg16: int

    @property
    def name(self) -> str:
        return EVENTS.get(self.event, f"event {self.event}")


@dataclass(frozen=True)
class Span:
    """One driver call, with the time it took."""
    name: str
    arg8: int
    start_us: int
    duration_us: int

    @property
    def ms(self) -> float:
        return self.duration_us / 1000.0


def parse_entries(payload: bytes) -> list[TraceEntry]:
    """Decodes one TRACE frame. A trailing partial entry is dropped."""
    out = []
    for offset in range(0, len(payload) - ENTRY_LEN + 1, ENTRY_LEN):
        us, event, arg8, arg16 = ENTRY.unpack_from(payload, offset)
        out.append(TraceEntry(us, event, arg8, arg16))
    return out


def spans(entries: list[TraceEntry]) -> list[Span]:
    """Pairs entry and exit events into durations.

    The board's timestamp is the low 32 bits of a microsecond counter, so it
    wraps about every 71 minutes. A pair that appears to end before it began
    is corrected by one wrap rather than reported as negative.

    Unmatched opens are skipped rather than guessed at: the ring may have been
    dumped mid-call, or wrapped and lost the closing event.
    """
    open_spans: dict[tuple[int, int], TraceEntry] = {}
    out: list[Span] = []
    for entry in entries:
        key = (entry.event, entry.arg8)
        if entry.event in SPANS:
            open_spans[key] = entry
            continue
        for start_event, end_event in SPANS.items():
            if entry.event != end_event:
                continue
            start = open_spans.pop((start_event, entry.arg8), None)
            if start is None:
                break
            elapsed = entry.us - start.us
            if elapsed < 0:
                elapsed += 1 << 32
            out.append(Span(EVENTS.get(start_event, str(start_event))
                            .replace(" in", ""),
                            entry.arg8, start.us, elapsed))
            break
    return out


def slowest(entries: list[TraceEntry], limit: int = 10) -> list[Span]:
    return sorted(spans(entries), key=lambda s: -s.duration_us)[:limit]
