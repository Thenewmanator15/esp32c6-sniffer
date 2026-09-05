"""Measures the real difference between the board's two antennas.

The XIAO ESP32-C6 has an onboard ceramic antenna and a U.FL connector, with a
switch between them. Community figures for the external antenna's advantage
disagree: one source says 5 dB, another about 10. Neither is a vendor
specification. This measures it on the actual board.

Method: alternate antennas in short blocks rather than measuring one then the
other. Ambient traffic drifts, so a single A-then-B comparison would confound
the antenna with whatever changed in between. Interleaving cancels slow drift.

Comparison is by median signal strength, not mean: signal distributions have
long tails from occasional close transmitters, and a median is not dragged
about by a handful of them.

    python tools/antenna_compare.py --port COM3 --channel 11

If the external antenna measures much WORSE, the most likely explanation is
that no U.FL antenna is fitted, in which case the switch is feeding an open
connector.
"""

from __future__ import annotations

import argparse
import statistics
import struct
import time

import serial

from esp32c6_sniffer.control import Antenna, Command, decode_reply, encode_command
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser

_META = struct.Struct("<BBbBQ")


def _open(port: str) -> serial.Serial:
    ser = serial.Serial(port, 115200, timeout=0.05)
    try:
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    return ser


def _command(ser, parser, command: Command, value: int = 0, timeout: float = 5.0):
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


def _collect(ser, parser, seconds: float) -> tuple[list[int], list[int]]:
    rssi, lqi = [], []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        for frame in parser.feed(ser.read(8192)):
            if frame.ftype is FrameType.PACKET and len(frame.payload) > _META.size:
                _ch, l, r, _f, _ts = _META.unpack_from(frame.payload)
                rssi.append(r)
                lqi.append(l)
    return rssi, lqi


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--channel", type=int, default=11)
    ap.add_argument("--block-s", type=float, default=15.0)
    ap.add_argument("--rounds", type=int, default=4)
    args = ap.parse_args()

    ser = _open(args.port)
    parser = StreamParser()
    _command(ser, parser, Command.SET_CHANNEL, args.channel)

    data: dict[Antenna, dict[str, list[int]]] = {
        Antenna.INTERNAL: {"rssi": [], "lqi": []},
        Antenna.EXTERNAL: {"rssi": [], "lqi": []},
    }

    print(f"channel {args.channel}, {args.rounds} rounds of "
          f"{args.block_s:.0f}s per antenna, interleaved")
    for round_no in range(1, args.rounds + 1):
        for antenna in (Antenna.INTERNAL, Antenna.EXTERNAL):
            _command(ser, parser, Command.SET_ANTENNA, int(antenna))
            time.sleep(0.4)          # let the switch settle
            parser.feed(ser.read(65536))   # drain anything mid-switch
            rssi, lqi = _collect(ser, parser, args.block_s)
            data[antenna]["rssi"] += rssi
            data[antenna]["lqi"] += lqi
            print(f"  round {round_no} {antenna.name:8s}: {len(rssi):4d} frames"
                  + (f", median {statistics.median(rssi):6.1f} dBm" if rssi else ""))

    _command(ser, parser, Command.SET_ANTENNA, int(Antenna.INTERNAL))
    ser.write(encode_command(Command.STOP))
    ser.flush()
    ser.close()

    print()
    print(f"{'antenna':10s} {'frames':>7} {'median dBm':>11} {'median LQI':>11}")
    summary = {}
    for antenna in (Antenna.INTERNAL, Antenna.EXTERNAL):
        rssi = data[antenna]["rssi"]
        lqi = data[antenna]["lqi"]
        if not rssi:
            print(f"{antenna.name:10s} {0:>7}  no frames")
            continue
        summary[antenna] = (statistics.median(rssi), len(rssi))
        print(f"{antenna.name:10s} {len(rssi):>7} {statistics.median(rssi):>11.1f} "
              f"{statistics.median(lqi):>11.1f}")

    if len(summary) == 2:
        delta = summary[Antenna.EXTERNAL][0] - summary[Antenna.INTERNAL][0]
        print()
        print(f"external minus internal: {delta:+.1f} dB (median)")
        if delta < -3:
            print("External is WORSE. Most likely no U.FL antenna is fitted,")
            print("so the switch is feeding an open connector.")
        elif abs(delta) <= 3:
            print("No meaningful difference at this signal level.")
        else:
            print("External is better, as expected with an antenna fitted.")
        print()
        print("Frame counts differ between antennas partly because a weaker")
        print("antenna simply hears fewer transmitters, so treat the counts as")
        print("a second signal rather than as noise in the median.")


if __name__ == "__main__":
    main()
