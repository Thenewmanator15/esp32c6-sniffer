"""Spectrum survey: RF energy per 802.15.4 channel.

Answers a question captures cannot. A capture shows what was transmitted while
you happened to be listening; this measures raw energy, so it sees a channel
that is busy with something it cannot decode. That matters in the 2.4 GHz band,
where Wi-Fi overlaps most of the 802.15.4 channels and is the usual reason a
mesh performs badly.

    python tools/spectrum.py --port COM3
    python tools/spectrum.py --port COM3 --passes 5 --dwell-ms 20

Wi-Fi channel overlap, for reading the output. Each Wi-Fi channel is about
22 MHz wide against 802.15.4's 2 MHz, so one Wi-Fi network covers roughly four
802.15.4 channels:

    Wi-Fi 1  (2412 MHz) covers 802.15.4 channels 11-14
    Wi-Fi 6  (2437 MHz) covers 802.15.4 channels 16-19
    Wi-Fi 11 (2462 MHz) covers 802.15.4 channels 21-24

Channels 15, 20, 25 and 26 sit in the gaps between the three non-overlapping
Wi-Fi channels, which is why Zigbee deployments favour them.
"""

from __future__ import annotations

import argparse
import statistics
import time

import serial

from esp32c6_sniffer.control import Command, decode_reply, encode_command
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.tap import CHANNEL_MAX, CHANNEL_MIN

# Channels Zigbee deployments commonly use, and the Wi-Fi gaps.
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


def _command(ser, parser, command: Command, value: int, timeout: float = 5.0) -> dict:
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


def _bar(dbm: float, floor: int = -100, ceiling: int = -20, width: int = 40) -> str:
    span = ceiling - floor
    filled = max(0, min(width, round((dbm - floor) / span * width)))
    return "#" * filled + "." * (width - filled)


def main() -> None:
    ap = argparse.ArgumentParser(description="802.15.4 spectrum survey")
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--passes", type=int, default=5,
                    help="sweeps over all channels; more passes average better")
    ap.add_argument("--dwell-ms", type=float, default=20.0,
                    help="measurement window per channel per pass")
    args = ap.parse_args()

    symbols = max(1, int(args.dwell_ms * 1000 / 16))  # 16 us per symbol
    ser = _open(args.port)
    parser = StreamParser()

    readings: dict[int, list[int]] = {
        c: [] for c in range(CHANNEL_MIN, CHANNEL_MAX + 1)
    }

    print(f"{args.passes} passes, {args.dwell_ms:.0f} ms per channel "
          f"({symbols} symbols)")
    try:
        for pass_no in range(1, args.passes + 1):
            for channel in range(CHANNEL_MIN, CHANNEL_MAX + 1):
                reply = _command(
                    ser, parser, Command.ENERGY_DETECT,
                    channel | (symbols << 8),
                )
                if not reply["ok"]:
                    continue
                raw = reply["value"] & 0xFF
                readings[channel].append(raw - 256 if raw > 127 else raw)
            print(f"  pass {pass_no} done")
    finally:
        ser.write(encode_command(Command.STOP))
        ser.flush()
        ser.close()

    print()
    print(f"{'ch':>3} {'MHz':>5} {'peak':>6} {'median':>7}  "
          f"{'':<40}  notes")
    quietest: list[tuple[float, int]] = []
    for channel in range(CHANNEL_MIN, CHANNEL_MAX + 1):
        values = readings[channel]
        if not values:
            print(f"{channel:>3} {channel_mhz(channel):>5}  no reading")
            continue
        peak = max(values)
        median = statistics.median(values)
        quietest.append((median, channel))
        notes = []
        if channel in WIFI_OVERLAP:
            notes.append(WIFI_OVERLAP[channel])
        if channel in ZIGBEE_PREFERRED:
            notes.append("Zigbee-preferred")
        print(f"{channel:>3} {channel_mhz(channel):>5} {peak:>6} {median:>7.1f}  "
              f"{_bar(median)}  {', '.join(notes)}")

    if quietest:
        quietest.sort()
        print()
        best = ", ".join(f"{c} ({m:.0f} dBm)" for m, c in quietest[:4])
        print(f"quietest channels: {best}")
        print()
        print("Energy is not the whole story: a quiet channel with a strong")
        print("neighbouring network on it is worse than a slightly noisier one")
        print("that is empty. Read this alongside a capture, not instead of one.")


if __name__ == "__main__":
    main()
