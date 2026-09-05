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

--recover fixes it. It power-gates the radio domain with a deep-sleep reset,
which is the only thing found to clear the latch: no driver rebuild, reflash or
erase-flash ever has. Measured going in: 0 access points before, 12 after.
"""

from __future__ import annotations

import argparse
import time

import serial

from esp32c6_sniffer.apscan import parse_ap_record
from esp32c6_sniffer.control import Command, Radio, decode_reply, encode_command
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.recovery import ensure_wifi_ready

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
                    if not reply["ok"]:
                        raise RuntimeError(
                            f"scan failed, status {reply['status']}"
                        )
                    # The reply arrives after the records, so it is the signal
                    # that the list is complete rather than merely quiet.
                    return found
    raise TimeoutError("no scan reply within the timeout")


def recover_and_rescan(port: str) -> list:
    """Power-gates the radio domain, waits for the board, and scans again.

    A deep-sleep reset is the only thing found to clear this board's latched
    deafness. It drops the USB link and the device re-enumerates, so the port
    is reopened rather than reused.
    """
    ser = serial.Serial(port, 115200, timeout=0.05)
    ser.write(encode_command(Command.RADIO_POWER_CYCLE, 0, radio=Radio.WIFI))
    ser.flush()
    time.sleep(2.0)
    ser.close()

    deadline = time.monotonic() + 30.0
    last = None
    ser = None
    while time.monotonic() < deadline:
        try:
            ser = serial.Serial(port, 115200, timeout=0.05)
            break
        except (OSError, serial.SerialException) as exc:
            last = exc
            time.sleep(0.5)
    if ser is None:
        raise RuntimeError(f"board did not come back on {port}: {last}")

    try:
        ser.reset_input_buffer()
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
                    help="if nothing is found, power-cycle the radio domain "
                         "and scan once more. Resets the board, so do not use "
                         "it while a capture is running")
    args = ap.parse_args()

    # Automatic rather than optional: if 802.15.4 has run since boot the
    # Wi-Fi receiver is deaf, and every scan would come back empty for a reason
    # that has nothing to do with the air.
    if ensure_wifi_ready(args.port):
        print("802.15.4 had been used; power-cycled the radio domain first.")

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
        print("Nothing found. Power-cycling the radio domain and retrying.")
        recovered = recover_and_rescan(args.port)
        best = {record.bssid: record for record in recovered}
        if best:
            print("The power cycle cleared it: the receiver was latched deaf.")

    if not best:
        print("\nNo access points found.")
        print("On this board that is not proof of an empty band: the Wi-Fi "
              "receiver latches deaf for minutes to hours.")
        if not args.recover:
            print("Try --recover, which power-cycles the radio domain and is "
                  "the only thing known to clear it.")
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
