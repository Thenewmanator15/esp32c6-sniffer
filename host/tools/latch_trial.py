"""Does leaving the 802.15.4 radio enabled deafen the Wi-Fi receiver?

The post-mortem answers "yes" from a three-row table with **one trial per arm**,
and its own closing lesson is "repeat before concluding, and alternate". That is
the gap this closes, and it is why nothing has been reported upstream: a vendor
is entitled to dismiss n=1.

    python tools/latch_trial.py --port COM3 --cycles 5

THE DESIGN, AND WHY EACH PIECE IS THERE
---------------------------------------
Three arms, differing only in how the 802.15.4 radio is left:

    dirty   started, then the port closed WITHOUT stopping it
    clean   started, stopped properly, then closed
    idle    port opened and closed, radio never started

*Interleaved, not blocked.* One arm runs, then the next, then the next, and the
order rotates every cycle. The fault comes in stretches lasting minutes to
hours, so running five of one arm and then five of another would confound the
treatment with whatever the receiver happened to be doing that quarter-hour.

*Every trial starts from a proven-working receiver.* Before each treatment the
radio domain is power-gated and a scan must return at least one access point.
A zero from an instrument nobody has proved is switched on measures the
instrument, not the world -- which is the mistake that produced three wrong
conclusions in the original investigation. A trial that cannot get a working
baseline is recorded as INVALID and excluded, rather than counted as a pass.

*Recovery is measured on the same trial.* When a treatment yields zero, the
domain is power-gated and scanned again. That turns each deaf reading into a
matched pair, so "the power-gate clears it" rests on the same events as "the
treatment caused it" rather than on two separate samples.

*The outcome is a count, scored as a proportion.* Access points found, not
frames. It is bounded, it does not depend on traffic happening to be sent, and
zero versus non-zero is unambiguous. The raw counts are written out too, so the
effect size is visible and not just its sign.

WHAT WOULD FALSIFY THE CLAIM
----------------------------
Deafness appearing in the clean or idle arms at a similar rate. The claim is
specifically that *leaving the radio enabled* does it -- not that using
802.15.4 at all does, and not that the receiver simply fails on its own.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import serial  # noqa: E402

from esp32c6_sniffer.control import (  # noqa: E402
    Command, Radio, decode_reply, encode_command,
)
from esp32c6_sniffer.framing import FrameType  # noqa: E402
from esp32c6_sniffer.parser import StreamParser  # noqa: E402
from esp32c6_sniffer.recovery import _open  # noqa: E402
from esp32c6_sniffer.capture import CaptureSession  # noqa: E402
from esp32c6_sniffer.control import Antenna  # noqa: E402
from esp32c6_sniffer.scan import scan_access_points  # noqa: E402

ARMS = ("dirty", "clean", "idle")

#: START carries the channel as its value for 802.15.4 -- passing 0 is refused
#: as a bad value, which is how the first version of this script produced a
#: null result in which the radio had never actually been started. 15 is used
#: because there is Thread traffic there to prove the receiver is live.
TREATMENT_CHANNEL = 15

#: The Wi-Fi channel to capture on for --measure frames, and how long for.
WIFI_CHANNEL = 6
CAPTURE_S = 12.0

#: Long enough for the radio to be genuinely running, short enough that a full
#: trial is minutes rather than an afternoon.
DWELL_S = 8.0
#: After a deep-sleep reset the chip re-enumerates over USB.
SETTLE_S = 2.0
#: Opening the port resets the chip, and it does not answer commands until it
#: has come back. recovery.py waits 2 s and scan.py 3 s for the same reason;
#: without this the board simply does not reply and a treatment silently does
#: not happen. Learned the hard way: the first run of this script reported a
#: tidy null result in which not one command had been acknowledged.
OPEN_SETTLE_S = 3.0
#: A deep-sleep reset drops the USB device, so a handle opened across one is
#: stale and the next read raises rather than returning nothing.
POWER_CYCLE_SETTLE_S = 6.0


def ask(ser: serial.Serial, parser: StreamParser, command: Command,
        value: int = 0, radio: Radio = Radio.WIFI, wait: float = 3.0):
    ser.write(encode_command(command, value, radio=radio))
    ser.flush()
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        for frame in parser.feed(ser.read(4096)):
            if frame.ftype is FrameType.CONTROL_REPLY:
                reply = decode_reply(frame.payload)
                if reply["command"] is command:
                    return reply
    return None


def power_cycle(port: str) -> None:
    """Power-gates the RF domain with a deep-sleep reset."""
    ser = _open(port)
    try:
        time.sleep(OPEN_SETTLE_S)
        ask(ser, StreamParser(), Command.RADIO_POWER_CYCLE, wait=2.0)
    except (OSError, serial.SerialException):
        # The board vanishing mid-command is the reset arriving, not a failure.
        pass
    finally:
        try:
            ser.close()
        except (OSError, serial.SerialException):
            pass
    time.sleep(POWER_CYCLE_SETTLE_S)


def count_access_points(port: str) -> int | None:
    """One scan. None means the board never answered, which is not a zero."""
    try:
        return len(scan_access_points(port))
    except (OSError, RuntimeError, TimeoutError, serial.SerialException):
        return None


def count_wifi_frames(port: str, seconds: float = CAPTURE_S) -> int | None:
    """Promiscuous Wi-Fi frames on one channel.

    This is the measure the retracted table in the post-mortem used. A null
    result against a different instrument would not have answered it, so both
    are offered and both were run.
    """
    try:
        session = CaptureSession(port, channel=WIFI_CHANNEL,
                                 antenna=Antenna.INTERNAL, radio=Radio.WIFI)
        session.open()
    except (OSError, RuntimeError, TimeoutError, serial.SerialException):
        return None
    frames = 0
    try:
        deadline = time.monotonic() + seconds
        for _record, _ts, _len in session.records():
            frames += 1
            if time.monotonic() > deadline:
                break
    except (OSError, RuntimeError, serial.SerialException):
        return None
    finally:
        try:
            session.close()
        except (OSError, serial.SerialException):
            pass
    return frames


#: Chosen by --measure. Both were run for the write-up; neither showed an effect.
MEASURES = {"aps": count_access_points, "frames": count_wifi_frames}


def apply_arm(port: str, arm: str) -> tuple[bool, int]:
    """Leaves the board in the state this arm is named for.

    Returns whether every command was acknowledged. A treatment nobody proved
    happened is the same mistake as a zero nobody proved -- a silently failed
    START would turn the dirty arm into another idle arm and make the whole
    trial meaningless while still producing a tidy table.
    """
    ser = _open(port)
    parser = StreamParser()
    try:
        time.sleep(OPEN_SETTLE_S)
        if arm == "idle":
            reply = ask(ser, parser, Command.GET_INFO)
            time.sleep(DWELL_S)
            return bool(reply and reply["ok"]), 0
        acks = [
            ask(ser, parser, Command.SET_RADIO, int(Radio.IEEE802154),
                radio=Radio.IEEE802154),
            ask(ser, parser, Command.START, TREATMENT_CHANNEL,
                radio=Radio.IEEE802154),
        ]
        # Count what the radio actually hears. An acknowledged START is not
        # proof the receiver ran; frames arriving are.
        heard = 0
        deadline = time.monotonic() + DWELL_S
        while time.monotonic() < deadline:
            for frame in parser.feed(ser.read(4096)):
                if frame.ftype is FrameType.PACKET:
                    heard += 1
        if arm == "clean":
            acks.append(ask(ser, parser, Command.STOP, radio=Radio.IEEE802154))
            time.sleep(0.5)
        # "dirty" closes the port with the radio still enabled, which is what
        # an ad-hoc script that forgets to stop does.
        return all(r is not None and r["ok"] for r in acks), heard
    finally:
        ser.close()


def read_dirty_flag(port: str) -> bool | None:
    """The board's own view of whether 802.15.4 still owns the front end.

    This is the treatment check. It survives the reset that opening the port
    causes, which is the whole reason the firmware keeps it in RTC_NOINIT
    memory.
    """
    ser = _open(port)
    try:
        time.sleep(OPEN_SETTLE_S)
        reply = ask(ser, StreamParser(), Command.RADIO_DIRTY)
        if reply is None or not reply["ok"]:
            return None
        return bool(reply["value"])
    finally:
        ser.close()


def trial(port: str, arm: str, cycle: int, verbose: bool, measure) -> dict:
    row = {"cycle": cycle, "arm": arm, "baseline": None, "applied": None,
           "dirty_flag": None, "heard": None, "after": None,
           "recovered": None, "valid": False, "deaf": None}

    # 1. Prove the instrument reads non-zero before trusting any zero from it.
    try:
        power_cycle(port)
        baseline = measure(port)
        if not baseline:
            power_cycle(port)
            baseline = measure(port)
    except (OSError, RuntimeError, serial.SerialException) as exc:
        if verbose:
            print(f"  cycle {cycle} {arm:<5}  INVALID: baseline failed: {exc}")
        return row
    row["baseline"] = baseline
    if not baseline:
        if verbose:
            print(f"  cycle {cycle} {arm:<5}  INVALID: no working baseline")
        return row

    # 2. Treatment, and proof it took.
    try:
        row["applied"], row["heard"] = apply_arm(port, arm)
        row["dirty_flag"] = read_dirty_flag(port)
    except (OSError, RuntimeError, serial.SerialException) as exc:
        if verbose:
            print(f"  cycle {cycle} {arm:<5}  INVALID: {exc}")
        return row
    if not row["applied"]:
        if verbose:
            print(f"  cycle {cycle} {arm:<5}  INVALID: treatment not acked")
        return row

    # 3. Outcome.
    after = measure(port)
    row["after"] = after
    if after is None:
        if verbose:
            print(f"  cycle {cycle} {arm:<5}  INVALID: board did not answer")
        return row

    row["valid"] = True
    row["deaf"] = after == 0

    # 4. Matched recovery, measured on this same trial.
    if after == 0:
        power_cycle(port)
        row["recovered"] = measure(port)

    if verbose:
        note = ""
        if row["deaf"]:
            note = f"  -> DEAF, {row['recovered']} after power-gate"
        flag = {True: "dirty", False: "clean", None: "?"}[row["dirty_flag"]]
        print(f"  cycle {cycle} {arm:<5}  baseline {baseline:>2} "
              f"-> after {after:>2}  heard={row['heard']:<4} "
              f"flag={flag}{note}")
    return row


def summarise(rows: list[dict]) -> None:
    valid = [r for r in rows if r["valid"]]
    print()
    print(f"  {len(valid)} valid trials of {len(rows)} attempted")
    print()
    print("  arm     n   deaf   rate   counts after treatment")
    print("  " + "-" * 56)
    for arm in ARMS:
        got = [r for r in valid if r["arm"] == arm]
        if not got:
            continue
        deaf = sum(1 for r in got if r["deaf"])
        counts = ",".join(str(r["after"]) for r in got)
        print(f"  {arm:<6} {len(got):>2}   {deaf:>3}   {deaf / len(got):>4.0%}"
              f"   {counts}")

    print()
    print("  treatment check -- did the board report the front end still owned?")
    for arm in ARMS:
        got = [r for r in valid if r["arm"] == arm]
        if got:
            flags = ",".join({True: "dirty", False: "clean", None: "?"}[r["dirty_flag"]]
                             for r in got)
            print(f"    {arm:<6} {flags}")

    recoveries = [r for r in valid if r["deaf"]]
    if recoveries:
        healed = sum(1 for r in recoveries if (r["recovered"] or 0) > 0)
        print()
        print(f"  power-gate recovered {healed} of {len(recoveries)} deaf "
              f"trials: "
              + ",".join(str(r["recovered"]) for r in recoveries))

    dirty = [r for r in valid if r["arm"] == "dirty"]
    others = [r for r in valid if r["arm"] != "dirty"]
    if dirty and others:
        a = sum(1 for r in dirty if r["deaf"])
        b = sum(1 for r in others if r["deaf"])
        print()
        print(f"  dirty {a}/{len(dirty)} deaf vs {b}/{len(others)} for the "
              "other two arms combined")
        if a == len(dirty) and b == 0:
            print("  a clean split: every dirty trial deaf, no other trial deaf")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--cycles", type=int, default=5,
                    help="trials per arm (default 5)")
    ap.add_argument("--csv", default=None, help="write every trial here")
    ap.add_argument("--measure", choices=sorted(MEASURES), default="aps",
                    help="aps: access points from a scan (fast). frames: "
                         "promiscuous Wi-Fi frames, which is what the "
                         "post-mortem's retracted table used (slower)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    verbose = not args.quiet
    measure = MEASURES[args.measure]
    print(f"latch trial: {args.cycles} cycles x {len(ARMS)} arms on {args.port}"
          f", measuring {args.measure}")
    print(f"each trial power-gates first and requires a non-zero baseline")
    print()

    rows: list[dict] = []
    for cycle in range(1, args.cycles + 1):
        # Rotate, so no arm always follows the same predecessor.
        order = list(itertools.islice(
            itertools.cycle(ARMS), cycle - 1, cycle - 1 + len(ARMS)))
        for arm in order:
            rows.append(trial(args.port, arm, cycle, verbose, measure))

    summarise(rows)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n  wrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
