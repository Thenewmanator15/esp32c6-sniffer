"""Wi-Fi survey: which access points are there, and on which channels.

The counterpart to spectrum.py. That one measures raw energy across the
802.15.4 channels; this one asks the Wi-Fi receiver what it can actually
identify, which is the other half of the same question in a shared band.

    python tools/wifi_survey.py --port COM3
    python tools/wifi_survey.py --port COM3 --repeat 3

Passive by default: it listens for beacons and transmits nothing. `--active`
sends probe requests, which is faster and finds access points that are not
beaconing at that moment, at the cost of announcing the sniffer's presence.

Useful before a capture, because a Wi-Fi capture is single-channel: this says
which channel is worth sitting on. The 802.15.4 overlap is printed alongside,
since one Wi-Fi network covers roughly four 802.15.4 channels and is the usual
reason a mesh performs badly.

A note specific to this board: its Wi-Fi receiver latches deaf, for anything
from minutes to hours (see docs/2026-09-05-wifi-investigation-postmortem.md).
An empty result is therefore not evidence of an empty band.

--recover fixes it. It starts the 802.15.4 radio and stops it cleanly, which
hands the shared front end back: it has cured every episode of the deafness
802.15.4 left running causes it was tried on, where the deep-sleep power-gate
this used to do left two of them deaf (2026-09-26 and 27). If that does not
find anything it power-gates as well, which usually cures that deafness too,
and did cure one with some other cause: 0 access points before, 12 after.
"""

from __future__ import annotations

import argparse
import sys
import time

import serial

from esp32c6_sniffer import boards
from esp32c6_sniffer.apscan import parse_ap_record
from esp32c6_sniffer.control import Command, Radio, decode_reply, encode_command
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.scan import IncompleteScan, scan_result
from esp32c6_sniffer.recovery import _open, ensure_wifi_ready, hand_back, power_cycle

# One Wi-Fi channel is about 22 MHz wide against 802.15.4's 2 MHz.
WIFI_TO_154 = {1: "11-14", 6: "16-19", 11: "21-24"}


def overlap_note(channel: int) -> str:
    if channel in WIFI_TO_154:
        return f"802.15.4 ch {WIFI_TO_154[channel]}"
    # Every 2.4 GHz Wi-Fi channel overlaps something; only the three
    # non-overlapping ones have a tidy mapping worth printing.
    low = 11 + max(0, (channel - 1)) * 5 // 5
    return f"~802.15.4 ch {min(26, low)}+"


def bar(rssi: int, width: int = 30) -> str:
    """-90 dBm or worse is empty, -30 dBm or better is full."""
    fraction = max(0.0, min(1.0, (rssi + 90) / 60.0))
    filled = round(fraction * width)
    return "#" * filled + "." * (width - filled)


def scan_once(ser: serial.Serial, parser: StreamParser,
              timeout: float = 20.0, active: bool = False) -> list:
    ser.write(encode_command(Command.SET_RADIO, int(Radio.WIFI),
                             radio=Radio.WIFI))
    ser.flush()
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        parser.feed(ser.read(4096))

    ser.write(encode_command(Command.WIFI_SCAN, 1 if active else 0,
                             radio=Radio.WIFI))
    ser.flush()

    found = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for frame in parser.feed(ser.read(8192)):
            if frame.ftype is FrameType.AP_RECORD:
                try:
                    found.append(parse_ap_record(frame.payload))
                except ValueError as exc:
                    print(f"  skipping a malformed AP record: {exc}")
            elif frame.ftype is FrameType.CONTROL_REPLY:
                reply = decode_reply(frame.payload)
                if reply["command"] is Command.WIFI_SCAN:
                    # The reply arrives after the records, so it is the signal
                    # that the list is complete rather than merely quiet --
                    # and it says how many there should have been.
                    try:
                        return scan_result(found, reply)
                    except IncompleteScan as exc:
                        print(f"  WARNING: {exc}; showing those that arrived")
                        return exc.found
    raise TimeoutError("no scan reply within the timeout")


def recover_and_rescan(port: str) -> tuple[list, str]:
    """Hands the front end back and scans again; power-gates and scans once
    more if that finds nothing. Returns what was found and which did it.

    Both reset the board, so the port is reopened rather than reused.
    """
    hand_back(port)
    found = _rescan(port)
    if found:
        return found, "handing the radio back"
    power_cycle(port)
    return _rescan(port), "power-cycling the radio domain"


def _rescan(port: str) -> list:
    ser = _open(port)
    try:
        time.sleep(2.0)
        return scan_once(ser, StreamParser())
    finally:
        ser.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--repeat", type=int, default=1,
                    help="scan this many times and merge, keeping the "
                         "strongest sighting of each access point")
    ap.add_argument("--active", action="store_true",
                    help="transmit probe requests. Faster and finds access "
                         "points that are not beaconing right now, but it "
                         "makes the sniffer visible on the air. Off by "
                         "default: this instrument listens")
    ap.add_argument("--recover", action="store_true",
                    help="if nothing is found, hand the radio back (start "
                         "and stop 802.15.4) and scan again, then power-cycle "
                         "the radio domain if need be. Resets the board, so do "
                         "not use it while a capture is running")
    args = ap.parse_args()

    # Refused before anything is sent. The first thing this does is
    # power-cycle the C6's radio domain, which would reach the nRF54L15 as a
    # command it answers with a timeout rather than a reason.
    board = boards.board_on_port(args.port)
    if board is not None and "wifi" not in board["radios"]:
        print(f"The {board['display']} on {args.port} has no Wi-Fi radio; "
              f"this survey needs the ESP32-C6.", file=sys.stderr)
        return 2

    # Automatic rather than optional: if 802.15.4 was left running the Wi-Fi
    # receiver is deaf, and every scan would come back empty for a reason
    # that has nothing to do with the air.
    if ensure_wifi_ready(args.port):
        print("802.15.4 had been left running; handed the radio back first.")

    ser = serial.Serial(args.port, 115200, timeout=0.05)
    try:
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    parser = StreamParser()

    best = {}
    empty_scans = 0
    try:
        for attempt in range(1, args.repeat + 1):
            if args.repeat > 1:
                print(f"scan {attempt} of {args.repeat}...")
            found = scan_once(ser, parser, active=args.active)
            if not found:
                empty_scans += 1
            for ap_record in found:
                seen = best.get(ap_record.bssid)
                if seen is None or ap_record.rssi_dbm > seen.rssi_dbm:
                    best[ap_record.bssid] = ap_record
    finally:
        ser.close()

    if not best and args.recover:
        print()
        print("Nothing found. Handing the radio back and retrying.")
        recovered, how = recover_and_rescan(args.port)
        best = {record.bssid: record for record in recovered}
        if best:
            print(f"Cleared by {how}: the receiver was latched deaf.")

    if not best:
        print("\nNo access points found.")
        print("On this board that is not proof of an empty band: the Wi-Fi "
              "receiver latches deaf for minutes to hours.")
        if not args.recover:
            print("Try --recover, which hands the radio back and, if that "
                  "does not do it, power-cycles the radio domain.")
        print("tools/spectrum.py uses the 802.15.4 radio and keeps working "
              "when Wi-Fi does not, so it is a useful second opinion.")
        return 0

    rows = sorted(best.values(), key=lambda a: -a.rssi_dbm)
    print()
    print(f"{'ch':>3}  {'RSSI':>5}  {'signal':<30}  {'security':<14}  SSID")
    for record in rows:
        name = "<hidden>" if record.hidden else record.ssid
        print(f"{record.channel:>3}  {record.rssi_dbm:>5}  "
              f"{bar(record.rssi_dbm):<30}  {record.auth_name:<14}  {name}")

    busiest = {}
    for record in rows:
        busiest[record.channel] = busiest.get(record.channel, 0) + 1
    print("\naccess points per channel:")
    for channel in sorted(busiest):
        print(f"  ch {channel:<3} {busiest[channel]:>2}   {overlap_note(channel)}")

    quietest = [c for c in (1, 6, 11) if c not in busiest]
    if quietest:
        print(f"\nunused non-overlapping channels: "
              f"{', '.join(str(c) for c in quietest)}")
    print("\nA capture is single-channel. Pick the channel carrying the "
          "traffic you want, not the quietest one.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
