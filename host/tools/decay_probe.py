"""Diagnostic: does throughput decay over time, or collapse on port reopen?

Background: the first benchmark run after a flash measures ~731 kB/s, and every
run after it measures ~411 kB/s. Two candidate causes, with very different
consequences:

  (a) Time decay. Something degrades the longer the link runs. That would be a
      real defect affecting live captures.
  (b) Reopen artefact. Closing the port leaves the firmware streaming into a
      host that is not reading, and reopening never recovers. That would mean
      the transport does not survive a consumer stall, which matters because
      Wireshark can stall.

This holds ONE port open and reports per-window throughput, then closes and
reopens and measures again. If windows stay flat and only the reopen drops,
it is (b). If windows decline within a single session, it is (a).
"""

from __future__ import annotations

import argparse
import time

import serial

from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser


def _open(port: str) -> serial.Serial:
    ser = serial.Serial(port, 115200, timeout=0.05)
    try:
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    return ser


def measure_windows(ser: serial.Serial, windows: int, window_s: float) -> list[float]:
    parser = StreamParser()
    rates = []
    for _ in range(windows):
        payload = 0
        start = time.monotonic()
        end = start + window_s
        while time.monotonic() < end:
            chunk = ser.read(8192)
            if not chunk:
                continue
            for frame in parser.feed(chunk):
                if frame.ftype is FrameType.PACKET:
                    payload += len(frame.payload) + 10
        rates.append(payload / (time.monotonic() - start) / 1000)
    return rates


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--windows", type=int, default=6)
    ap.add_argument("--window-s", type=float, default=10.0)
    ap.add_argument("--gap-s", type=float, default=5.0,
                    help="seconds with the port CLOSED before the second session")
    args = ap.parse_args()

    print(f"session 1: one continuous open, {args.windows} x {args.window_s}s")
    ser = _open(args.port)
    first = measure_windows(ser, args.windows, args.window_s)
    ser.close()
    for i, r in enumerate(first, 1):
        print(f"  window {i}: {r:7.1f} kB/s")

    print(f"\nport closed for {args.gap_s}s (firmware streams into nothing)")
    time.sleep(args.gap_s)

    print(f"session 2: reopened, {args.windows} x {args.window_s}s")
    ser = _open(args.port)
    second = measure_windows(ser, args.windows, args.window_s)
    ser.close()
    for i, r in enumerate(second, 1):
        print(f"  window {i}: {r:7.1f} kB/s")

    print()
    print(f"session 1 mean: {sum(first)/len(first):7.1f} kB/s")
    print(f"session 2 mean: {sum(second)/len(second):7.1f} kB/s")
    drift_1 = (first[-1] - first[0]) / first[0] * 100 if first[0] else 0.0
    print(f"within-session-1 drift: {drift_1:+.1f}%")
    print()
    if abs(drift_1) > 15:
        print("=> DECAY OVER TIME: degrades within a single open session.")
    elif sum(second) / len(second) < 0.8 * (sum(first) / len(first)):
        print("=> REOPEN ARTEFACT: flat while open, collapses after a stall.")
    else:
        print("=> Neither reproduced in this run.")


if __name__ == "__main__":
    main()
