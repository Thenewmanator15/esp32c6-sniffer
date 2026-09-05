"""Full channel survey: energy floor and actual traffic, side by side.

Answers "which channel are the networks on, and which channel is clean", which
takes a lot of manual work otherwise. Nordic have an open feature request for
exactly this on their own sniffer, with the rationale that discovering an
unknown network's channel is otherwise slow guesswork.

The two halves measure genuinely different things and neither substitutes for
the other:

* **Energy** is measured by the radio's detector and sees anything radiating,
  including the Wi-Fi that overlaps most 802.15.4 channels. It works on a
  channel carrying nothing decodable.
* **Traffic** is decoded frames. A channel can be electrically noisy and carry
  no 802.15.4 at all, or be quiet and carry a network talking softly.

Read them together. A quiet channel occupied by a strong neighbouring network
is a worse choice than a noisier empty one.

    python tools/survey.py --port COM3
    python tools/survey.py --port COM3 --dwell 15 --channels 11,15,20,25
"""

from __future__ import annotations

import argparse
import statistics
import struct
import time

import serial

from esp32c6_sniffer.control import Command, decode_reply, encode_command
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.tap import CHANNEL_MAX, CHANNEL_MIN

_META = struct.Struct("<BBbBQ")

ZIGBEE_PREFERRED = {11, 15, 20, 25, 26}
WIFI_OVERLAP = {
    **{c: "Wi-Fi 1" for c in range(11, 15)},
    **{c: "Wi-Fi 6" for c in range(16, 20)},
    **{c: "Wi-Fi 11" for c in range(21, 25)},
}


def channel_mhz(channel: int) -> int:
    return 2405 + 5 * (channel - CHANNEL_MIN)


def _open(port: str) -> serial.Serial:
    ser = serial.Serial(port, 115200, timeout=0.05)
    try:
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    return ser


def _command(ser, parser, command: Command, value: int, timeout: float = 5.0):
    ser.write(encode_command(command, value))
    ser.flush()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for frame in parser.feed(ser.read(4096)):
            if frame.ftype is FrameType.CONTROL_REPLY:
                reply = decode_reply(frame.payload)
                if reply["command"] is command:
                    return reply
    raise TimeoutError(f"no reply to {command.name}")


def main() -> None:
    ap = argparse.ArgumentParser(description="802.15.4 channel survey")
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--dwell", type=float, default=8.0,
                    help="seconds listening for traffic per channel")
    ap.add_argument("--energy-passes", type=int, default=3)
    ap.add_argument("--channels", default="",
                    help="comma-separated subset, e.g. 11,15,20,25")
    args = ap.parse_args()

    if args.channels:
        channels = [int(c) for c in args.channels.split(",")]
    else:
        channels = list(range(CHANNEL_MIN, CHANNEL_MAX + 1))
    symbols = int(20_000 / 16)  # 20 ms per energy sample

    ser = _open(args.port)
    parser = StreamParser()
    energy: dict[int, list[int]] = {c: [] for c in channels}
    traffic: dict[int, dict] = {}

    total = len(channels) * args.dwell + args.energy_passes * len(channels) * 0.1
    print(f"surveying {len(channels)} channels, about {total/60:.1f} minutes")

    try:
        print(f"phase 1: energy, {args.energy_passes} passes")
        for _ in range(args.energy_passes):
            for channel in channels:
                reply = _command(ser, parser, Command.ENERGY_DETECT,
                                 channel | (symbols << 8))
                if reply["ok"]:
                    raw = reply["value"] & 0xFF
                    energy[channel].append(raw - 256 if raw > 127 else raw)

        print(f"phase 2: traffic, {args.dwell:.0f} s per channel")
        for channel in channels:
            _command(ser, parser, Command.SET_CHANNEL, channel)
            time.sleep(0.3)
            parser.feed(ser.read(65536))     # drain the retune boundary
            frames, rssis = 0, []
            end = time.monotonic() + args.dwell
            while time.monotonic() < end:
                for frame in parser.feed(ser.read(8192)):
                    if (frame.ftype is FrameType.PACKET
                            and len(frame.payload) > _META.size):
                        _c, _lqi, rssi, _f, _ts = _META.unpack_from(frame.payload)
                        frames += 1
                        rssis.append(rssi)
            traffic[channel] = {"frames": frames, "rssis": rssis}
            marker = f"{frames} frames" if frames else "quiet"
            print(f"  channel {channel:>2}: {marker}")
    finally:
        ser.write(encode_command(Command.STOP))
        ser.flush()
        ser.close()

    print()
    print(f"{'ch':>3} {'MHz':>5} {'noise':>6} {'frames':>7} {'/s':>6} "
          f"{'signal':>7}  notes")
    busy = []
    for channel in channels:
        e = energy[channel]
        t = traffic[channel]
        noise = f"{statistics.median(e):.0f}" if e else "-"
        rate = t["frames"] / args.dwell
        sig = f"{statistics.median(t['rssis']):.0f}" if t["rssis"] else "-"
        notes = []
        if t["frames"]:
            notes.append("NETWORK")
            busy.append((t["frames"], channel))
        if channel in WIFI_OVERLAP:
            notes.append(WIFI_OVERLAP[channel])
        if channel in ZIGBEE_PREFERRED:
            notes.append("Zigbee-preferred")
        print(f"{channel:>3} {channel_mhz(channel):>5} {noise:>6} "
              f"{t['frames']:>7} {rate:>6.1f} {sig:>7}  {', '.join(notes)}")

    print()
    if busy:
        busy.sort(reverse=True)
        found = ", ".join(f"ch {c} ({n} frames)" for n, c in busy)
        print(f"networks found on: {found}")
    else:
        print("no 802.15.4 traffic seen on any channel during the dwell.")
        print("That may be genuine, or the networks may simply have been idle:")
        print("a longer --dwell finds sparse traffic that a short one misses.")


if __name__ == "__main__":
    main()
