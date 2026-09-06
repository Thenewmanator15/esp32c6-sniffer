"""Where does the time go on the board?

Drives a capture the way Wireshark does, then reads the board's own event
trace to find out what each command actually cost. The host can only see one
round trip and cannot say which side spent it; this can.

    python tools/trace.py --port COM3 --radio ble
    python tools/trace.py --port COM3 --radio 802154 --channel 11

Turning the trace on clears it, so each run reports only its own events.
"""

from __future__ import annotations

import argparse
import time

import serial

from esp32c6_sniffer.control import (
    Command,
    Radio,
    decode_reply,
    encode_command,
)
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.trace import EVENTS, parse_entries, spans

RADIOS = {"802154": Radio.IEEE802154, "wifi": Radio.WIFI, "ble": Radio.BLE}

#: Commands, by id, for reading the trace back. Built from the enum so it
#: cannot drift the way a hand-written table would.
COMMAND_NAMES = {int(c): c.name for c in Command}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--radio", default="ble", choices=sorted(RADIOS))
    ap.add_argument("--channel", type=int, default=None)
    ap.add_argument("--seconds", type=float, default=8.0)
    args = ap.parse_args()

    radio = RADIOS[args.radio]
    channel = args.channel
    if channel is None:
        channel = {"802154": 11, "wifi": 6, "ble": 0}[args.radio]

    ser = serial.Serial(args.port, 115200, timeout=0.1)
    try:
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    parser = StreamParser()
    entries = []
    time.sleep(2.0)
    ser.reset_input_buffer()

    def pump(seconds, collect_trace=False, until=None, quiet_for=None):
        """Reads for `seconds`, or until `until` replies, whichever first.

        Returning early matters: timing a command by pumping for a fixed
        window measures the window, not the command. The first version of this
        tool reported STOP as taking 10004 ms, which was its own timeout.
        """
        replies = []
        end = time.time() + seconds
        last = time.time()
        while time.time() < end:
            data = ser.read(8192)
            for frame in parser.feed(data):
                if frame.ftype is FrameType.CONTROL_REPLY:
                    replies.append(decode_reply(frame.payload))
                    if until is not None and any(
                            r["command"] is until for r in replies):
                        return replies
                elif collect_trace and frame.ftype is FrameType.TRACE:
                    entries.extend(parse_entries(frame.payload))
                    last = time.time()
            # Trace frames arrive in a burst; stop once it has gone quiet
            # rather than waiting out the whole window.
            if quiet_for and entries and time.time() - last > quiet_for:
                return replies
        return replies

    def command(cmd, value=0, wait=6.0, collect_trace=False):
        started = time.time()
        ser.write(encode_command(cmd, value, radio=radio))
        ser.flush()
        for reply in pump(wait, collect_trace,
                          until=None if collect_trace else cmd,
                          quiet_for=0.4 if collect_trace else None):
            if reply["command"] is cmd:
                return reply, time.time() - started
        return None, time.time() - started

    print(f"tracing a {args.radio} capture on {args.port}", flush=True)
    command(Command.TRACE_ENABLE, 1)

    command(Command.SET_RADIO, int(radio))
    # BLE has no channel -- the controller rotates the three advertising
    # channels itself -- so START is what begins a capture there, while the
    # other two are started by being tuned.
    if radio is Radio.BLE:
        _reply, start_cost = command(Command.START, wait=8.0)
    else:
        _reply, start_cost = command(Command.SET_CHANNEL, channel, wait=8.0)
    print(f"  start   took {start_cost * 1000:7.0f} ms as seen by the host",
          flush=True)

    pump(args.seconds)

    _reply, stop_cost = command(Command.STOP, wait=10.0)
    print(f"  STOP    took {stop_cost * 1000:7.0f} ms as seen by the host",
          flush=True)

    reply, _ = command(Command.TRACE_DUMP, wait=8.0, collect_trace=True)
    total = reply["value"] if reply else 0
    command(Command.TRACE_ENABLE, 0)
    ser.close()

    print(f"\n{len(entries)} entries read, {total} recorded", end="")
    print(" (the ring wrapped; the beginning is lost)"
          if total > len(entries) else "")

    if not entries:
        print("\nNothing traced. Is the firmware new enough to have it?")
        return 1

    found = spans(entries)
    print("\nwhat the board spent its time in, slowest first:")
    print(f"  {'call':<28} {'arg':>3} {'ms':>9}")
    for span in sorted(found, key=lambda s: -s.duration_us)[:14]:
        name = span.name
        if name == "cmd":
            name = f"cmd {COMMAND_NAMES.get(span.arg8, span.arg8)}"
        print(f"  {name:<28} {span.arg8:>3} {span.ms:>9.1f}")

    stop = [s for s in found
            if s.name == "cmd" and COMMAND_NAMES.get(s.arg8) == "STOP"]
    if stop:
        inside = [s for s in found
                  if s.name != "cmd"
                  and stop[0].start_us <= s.start_us
                  <= stop[0].start_us + stop[0].duration_us]
        print(f"\nSTOP took {stop[0].ms:.1f} ms on the board. Inside it:")
        for span in sorted(inside, key=lambda s: -s.duration_us):
            print(f"  {span.name:<28} {span.arg8:>3} {span.ms:>9.1f}")
        # Only the outermost spans: the controller's disable and deinit
        # are nested inside the BLE stop, so summing everything counts them
        # twice and can exceed the total it is meant to explain.
        outer = [s for s in inside
                 if not any(o is not s
                            and o.start_us <= s.start_us
                            and s.start_us + s.duration_us
                            <= o.start_us + o.duration_us
                            for o in inside)]
        accounted = sum(s.duration_us for s in outer)
        print(f"  {'accounted for (top level)':<28} {'':>3} "
              f"{accounted / 1000:>9.1f}   of {stop[0].ms:.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
