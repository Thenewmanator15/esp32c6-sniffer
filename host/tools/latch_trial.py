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
front end is handed back -- 802.15.4 started and stopped cleanly -- the radio
domain is power-gated, and a scan must return at least one access point.
A zero from an instrument nobody has proved is switched on measures the
instrument, not the world -- which is the mistake that produced three wrong
conclusions in the original investigation. A trial that cannot get a working
baseline is recorded as INVALID and excluded, rather than counted as a pass.

*Recovery is measured on the same trial.* When a treatment yields zero, the
domain is power-gated and scanned again, then, if still deaf, the front end is
handed back and scanned again. That turns each deaf reading into a matched
set, so "this clears it" rests on the same events as "the treatment caused it"
rather than on separate samples.

WHAT IT FOUND, 2026-09-27
-------------------------
Dirty: deaf 8 times in 8. The power-gate cured it 0 times in 16, and an hour's
wait did not either; the hand-back cured it every time, with no time spent
receiving. So the firmware now hands back at boot when the flag is set, and
opening the port boots it -- which cures a dirty trial before it is measured.
Standard firmware therefore scores every dirty trial INVALID; measuring the
latch itself needs a build with -DSN_154_NO_BOOT_HANDBACK=1.

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
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import serial  # noqa: E402

from esp32c6_sniffer.control import (  # noqa: E402
    Command, Radio, decode_reply, encode_command,
)
from esp32c6_sniffer.framing import FrameType  # noqa: E402
from esp32c6_sniffer.parser import StreamParser  # noqa: E402
from esp32c6_sniffer.recovery import _open, hand_back  # noqa: E402
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
    """One scan. None means the board never answered, which is not a zero.

    recover=False, as for count_wifi_frames: the scan otherwise power-cycles
    a board whose 802.15.4 flag is set -- the dirty arm's -- so every dirty
    trial was cured before it was measured.
    """
    try:
        return len(scan_access_points(port, recover=False))
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
                                 antenna=Antenna.INTERNAL, radio=Radio.WIFI,
                                 recover=False)
        session.open()
    except (OSError, RuntimeError, TimeoutError, serial.SerialException):
        return None
    frames = 0
    # Stopped by a timer, not by a deadline checked between frames: a deaf
    # receiver yields none, and the check never ran -- the trial waited for
    # ever on exactly the state it exists to measure.
    timer = threading.Timer(seconds, session.request_stop)
    timer.start()
    try:
        for _record, _ts, _len in session.records():
            frames += 1
    except (OSError, RuntimeError, serial.SerialException):
        return None
    finally:
        timer.cancel()
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


def await_recovery(port: str, measure, limit_s: float, poll_s: float,
                   clock=time.monotonic, sleep=time.sleep) -> float | None:
    """Seconds until the receiver hears again on its own, or None.

    For a deaf trial the power-gate did not cure. The first properly
    measured dirty trial was one: fourteen power-gates in seven minutes all
    failed, every later trial read INVALID, and the receiver came back by
    itself some twenty minutes later. So rather than end the run, this waits
    -- measuring every poll_s, never power-gating -- and says how long it
    took, which is itself worth knowing. None from the measure is a board
    that did not answer, and does not count as heard.
    """
    start = clock()
    while clock() - start < limit_s:
        sleep(poll_s)
        if measure(port):
            return clock() - start
    return None


def trial(port: str, arm: str, cycle: int, verbose: bool, measure) -> dict:
    row = {"cycle": cycle, "arm": arm, "baseline": None, "applied": None,
           "dirty_flag": None, "heard": None, "after": None,
           "recovered": None, "handed_back": None, "valid": False,
           "deaf": None, "self_recovered_s": None}

    # 1. Prove the instrument reads non-zero before trusting any zero from it.
    # The hand-back first: a latch the last dirty trial left survives a
    # power-gate, and failed every later baseline until it was found.
    try:
        hand_back(port, settle=OPEN_SETTLE_S)
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
    # Reading the flag opened the port, which boots the board, and standard
    # firmware hands the front end back at boot when the flag is set: a
    # dirty arm reading clean was cured before it could be measured.
    if arm == "dirty" and row["dirty_flag"] is False:
        if verbose:
            print(f"  cycle {cycle} {arm:<5}  INVALID: the board handed the "
                  "front end back at boot; measuring the latch needs a "
                  "-DSN_154_NO_BOOT_HANDBACK=1 build")
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

    # 4. Matched recovery, measured on this same trial: the power-gate, then
    # the hand-back -- a clean 802.15.4 start and stop -- if that did not.
    if after == 0:
        power_cycle(port)
        row["recovered"] = measure(port)
        if not row["recovered"]:
            hand_back(port, settle=OPEN_SETTLE_S)
            row["handed_back"] = measure(port)

    if verbose:
        note = ""
        if row["deaf"]:
            note = f"  -> DEAF, {row['recovered']} after power-gate"
            if row["handed_back"] is not None:
                note += f", {row['handed_back']} after hand-back"
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
    ap.add_argument("--arms", default=None,
                    help="comma-separated arm sequence, overriding the default "
                         "rotation. Use it to put controls before the arm under "
                         "test, e.g. dirty,dirty,clean")
    ap.add_argument("--stop-on-deaf", action="store_true",
                    help="halt as soon as a deaf trial cannot be recovered by "
                         "a power-gate, rather than carry on into trials that "
                         "would all read INVALID")
    ap.add_argument("--await-recovery", type=float, default=0.0,
                    metavar="MINUTES",
                    help="after a deaf trial the power-gate did not cure, wait "
                         "up to this long for the receiver to hear again on its "
                         "own, time it, and carry on; halt if it does not")
    ap.add_argument("--poll-s", type=float, default=60.0,
                    help="how often to measure while waiting (default 60)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    verbose = not args.quiet
    measure = MEASURES[args.measure]
    print(f"latch trial: {args.cycles} cycles x {len(ARMS)} arms on {args.port}"
          f", measuring {args.measure}")
    print(f"each trial power-gates first and requires a non-zero baseline")
    print()

    fixed = None
    if args.arms:
        fixed = [a.strip() for a in args.arms.split(",") if a.strip()]
        bad = [a for a in fixed if a not in ARMS]
        if bad:
            sys.stderr.write("error: unknown arm(s) %s, choose from %s\n"
                             % (bad, list(ARMS)))
            return 1

    rows: list[dict] = []
    halted = False
    for cycle in range(1, args.cycles + 1):
        if fixed is not None:
            order = fixed
        else:
            # Rotate, so no arm always follows the same predecessor.
            order = list(itertools.islice(
                itertools.cycle(ARMS), cycle - 1, cycle - 1 + len(ARMS)))
        for arm in order:
            row = trial(args.port, arm, cycle, verbose, measure)
            rows.append(row)
            stuck = (row["valid"] and row["deaf"] and not row["recovered"]
                     and not row["handed_back"])
            if stuck and args.await_recovery > 0:
                if verbose:
                    print(f"    waiting up to {args.await_recovery:g} min for it "
                          f"to hear again on its own...")
                took = await_recovery(args.port, measure,
                                      args.await_recovery * 60, args.poll_s)
                row["self_recovered_s"] = took
                if took is not None:
                    if verbose:
                        print(f"    heard again after {took / 60:.1f} min")
                    continue
                print()
                print(f"  stopping: still deaf after {args.await_recovery:g} min.")
                halted = True
                break
            if args.stop_on_deaf and stuck:
                print()
                print("  stopping: deaf and the power-gate did not recover it.")
                print("  Unplugging the board clears it; so, given time, does")
                print("  waiting -- see --await-recovery.")
                halted = True
                break
        if halted:
            break

    summarise(rows)
    deaf = [r for r in rows if r["valid"] and r["deaf"] and not r["recovered"]]
    if deaf:
        cured = sum(1 for r in deaf if r["handed_back"])
        print(f"  hand-back recovered {cured} of the {len(deaf)} the "
              f"power-gate did not")
    waits = [r["self_recovered_s"] for r in rows
             if r["valid"] and r["deaf"] and not r["recovered"]
             and not r["handed_back"]]
    if waits:
        shown = ", ".join("never" if w is None else f"{w / 60:.1f} min"
                          for w in waits)
        print(f"  heard again on its own, power-gates having failed: {shown}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
        print(f"\n  wrote {args.csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
