"""Link probe: what the serial link loses between a board and the host.

Captures for a while, keeping every raw byte the host read, then walks them.
Frame headers carry their own CRC, so every intact header is a landmark: the
distance to the next must be exactly HEADER_LEN + length. A shortfall is bytes
cut from that frame's payload -- delivered corrupted, since nothing covers the
payload -- and a sequence gap is frames whose headers were lost outright.
Between two intact STATS frames the board's own bytes_sent says how much it
queued, so the total lost in transit is exact rather than estimated.

This is how the nRF54L15's link loss was pinned down: its SAMD11 bridge holds
319 bytes, and when its USB side pauses, the rest of any longer burst is gone.
See nrf54l15-sniffer's README for the measurements.

    python tools/link_probe.py --port COM4 --seconds 60
    python tools/link_probe.py --port COM4 --window 30 --interval 60
    python tools/link_probe.py --port COM4 --radio 802154 --channel 25 --dump run.bin
"""

from __future__ import annotations

import argparse
import pathlib
import struct
import sys
import time
from dataclasses import dataclass, field

from esp32c6_sniffer import boards
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Radio
from esp32c6_sniffer.framing import HEADER_LEN, MAGIC, FrameType, crc16_ccitt_false

_MAGIC_BYTES = struct.pack("<H", MAGIC)
_HEADER = struct.Struct("<HBBHH")          # magic, type, flags, seq, length

#: bytes_sent is the fifth counter of sn_link_stats_t, the first block of
#: every STATS payload: frames_sent, frames_dropped_ringfull, short_writes,
#: tx_stalls, bytes_sent.
BYTES_SENT_INDEX = 4

#: What the XIAO nRF54L15's SAMD11 bridge holds on its way to USB. A burst
#: longer than this is what a pause on the USB side cuts.
BRIDGE_BUFFER_BYTES = 319


@dataclass
class Truncated:
    frame_type: str
    declared: int      # payload length the header promised
    missing: int       # bytes of it that never arrived


@dataclass
class HeaderGap:
    after: str         # type of the last intact frame before the gap
    frames_lost: int


@dataclass
class LinkReport:
    headers: int = 0
    truncated: list[Truncated] = field(default_factory=list)
    header_gaps: list[HeaderGap] = field(default_factory=list)
    frames_over_bridge_buffer: int = 0
    #: Exact bytes lost between the first and last intact STATS frames, or
    #: None when there were not two to measure between -- unknown, not zero.
    lost_bytes: int | None = None
    seconds: int | None = None
    board_bytes_per_s: int | None = None


def _type_name(value: int) -> str:
    try:
        return FrameType(value).name
    except ValueError:
        return str(value)


def headers(raw: bytes) -> list[tuple[int, int, int, int]]:
    """(offset, type, seq, length) for every header whose CRC is intact."""
    found = []
    i = raw.find(_MAGIC_BYTES)
    while i != -1:
        if i + HEADER_LEN <= len(raw):
            crc = struct.unpack_from("<H", raw, i + 8)[0]
            if crc16_ccitt_false(raw[i:i + 8]) == crc:
                _magic, ftype, _flags, seq, length = _HEADER.unpack_from(raw, i)
                found.append((i, ftype, seq, length))
        i = raw.find(_MAGIC_BYTES, i + 1)
    return found


def analyse(raw: bytes) -> LinkReport:
    found = headers(raw)
    report = LinkReport(headers=len(found))
    intact = set()
    for (pos, ftype, seq, length), (npos, _nt, nseq, _nl) in zip(found, found[1:]):
        expected, actual = HEADER_LEN + length, npos - pos
        frames_lost = (nseq - seq - 1) & 0xFFFF
        if expected > BRIDGE_BUFFER_BYTES:
            report.frames_over_bridge_buffer += 1
        if actual == expected and frames_lost == 0:
            intact.add(pos)
        elif actual < expected:
            report.truncated.append(
                Truncated(_type_name(ftype), length, expected - actual))
        else:
            report.header_gaps.append(HeaderGap(_type_name(ftype), frames_lost))
    if found and HEADER_LEN + found[-1][3] > BRIDGE_BUFFER_BYTES:
        report.frames_over_bridge_buffer += 1

    # A STATS frame counts when it is intact -- or when it is the last frame
    # read and its whole payload arrived, since nothing follows to check it by.
    last_pos = found[-1][0] if found else -1

    def whole(pos, length):
        return pos in intact or (pos == last_pos
                                 and pos + HEADER_LEN + length <= len(raw))

    offset = HEADER_LEN + 4 * BYTES_SENT_INDEX
    counted = [(pos, struct.unpack_from("<I", raw, pos + offset)[0])
               for (pos, ftype, _seq, length) in found
               if ftype == FrameType.STATS and length >= 4 * (BYTES_SENT_INDEX + 1)
               and whole(pos, length)]
    if len(counted) >= 2:
        (first_pos, first_sent), (last_pos, last_sent) = counted[0], counted[-1]
        report.lost_bytes = (last_sent - first_sent) - (last_pos - first_pos)
        report.seconds = len(counted) - 1
        report.board_bytes_per_s = round((last_sent - first_sent) / report.seconds)
    return report


def capture(port: str, board: dict, radio: Radio, channel: int, seconds: float,
            interval: int, window: int, periodic: bool) -> tuple[bytes, object]:
    """Captures normally while keeping a copy of every byte the host read."""
    raw = bytearray()
    kwargs = {}
    if radio is Radio.BLE:
        kwargs = dict(ble_interval_ms=interval, ble_window_ms=window,
                      ble_periodic=periodic)
    session = CaptureSession(port, channel=channel, radio=radio,
                             board=board["id"], baud=board["baud"], **kwargs)
    session.open()
    try:
        # The session owns the port. Wrapping its read is the one way to see
        # the bytes before the parser does, which is the whole point here.
        read = session._serial.read

        def tee(n=1):
            data = read(n)
            raw.extend(data)
            return data

        session._serial.read = tee
        deadline = time.monotonic() + seconds
        for _record in session.records():
            if time.monotonic() > deadline:
                break
        stats = session.stats
    finally:
        session.close()
    return bytes(raw), stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--port", required=True)
    ap.add_argument("--radio", choices=("ble", "802154"), default="ble",
                    help="BLE by default: its batches are the long bursts")
    ap.add_argument("--channel", type=int, default=25,
                    help="802.15.4 channel, when --radio 802154")
    ap.add_argument("--seconds", type=float, default=60.0)
    ap.add_argument("--interval", type=int, default=60, help="BLE scan interval, ms")
    ap.add_argument("--window", type=int, default=60, help="BLE scan window, ms")
    ap.add_argument("--periodic", action="store_true",
                    help="follow periodic advertising too")
    ap.add_argument("--dump", type=pathlib.Path,
                    help="also write the raw bytes here, for another look later")
    args = ap.parse_args()

    board = boards.board_on_port(args.port) or boards.board_by_id("esp32c6")
    radio = Radio.BLE if args.radio == "ble" else Radio.IEEE802154
    channel = 0 if radio is Radio.BLE else args.channel
    print(f"probing the {board['display']} on {args.port} for "
          f"{args.seconds:.0f} s ({args.radio})", flush=True)

    raw, stats = capture(args.port, board, radio, channel, args.seconds,
                         args.interval, args.window, args.periodic)
    if args.dump:
        args.dump.write_bytes(raw)
    report = analyse(raw)

    if report.lost_bytes is None:
        lost = "unknown (fewer than two intact STATS frames)"
    else:
        lost = (f"{report.lost_bytes} B in {report.seconds} s, of "
                f"{report.board_bytes_per_s} B/s the board sent")
    print(f"received {len(raw)} B, {report.headers} frame headers intact")
    print(f"lost in transit: {lost}")
    print(f"frames longer than the bridge's {BRIDGE_BUFFER_BYTES} B: "
          f"{report.frames_over_bridge_buffer}")
    print(f"truncated frames: {len(report.truncated)}; header gaps: "
          f"{len(report.header_gaps)}")
    for t in report.truncated[:10]:
        print(f"  {t.frame_type} of {t.declared} B lost its last {t.missing} B")
    for g in report.header_gaps[:10]:
        print(f"  {g.frames_lost} frame(s) lost outright after a {g.after}")
    print(f"host: {stats.frames} records, {stats.sequence_gaps} sequence gaps, "
          f"{stats.resyncs} resyncs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
