"""Measures sustained USB throughput from the board.

No published throughput figure exists for the ESP32-C6's USB-Serial-JTAG
peripheral. The only comparable measurement is roughly 770 kB/s on an
ESP32-S3, against a theoretical full-speed bulk ceiling near 1.2 MB/s. This
produces the real number for this chip.

Flash a benchmark build first:

    idf.py build -DSN_MODE=1 -DSN_BENCH_PAYLOAD=256
    .\\flash.ps1 -Port COM3

Then:

    python -m esp32c6_sniffer.benchmark --port COM3 --seconds 20
"""

from __future__ import annotations

import argparse
import struct
import time

import serial

from .framing import FrameType
from .parser import SequenceTracker, StreamParser

# Matches sn_link_stats_t in firmware/main/usb_link.h
_STATS_STRUCT = struct.Struct("<5I")
_STATS_FIELDS = (
    "frames_sent",
    "frames_dropped_ringfull",
    "short_writes",
    "tx_stalls",
    "bytes_sent",
)


def run(port: str, seconds: float) -> dict:
    ser = serial.Serial(port, 115200, timeout=0.05)
    try:
        # pyserial opens Windows ports with only a 4 KB receive buffer. The
        # firmware discards data after 50 ms when the host stops draining, so
        # this is a correctness measure, not a performance tweak.
        ser.set_buffer_size(rx_size=1 << 20)
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()

    parser = StreamParser()
    tracker = SequenceTracker()
    payload_bytes = 0
    framed_bytes = 0
    packet_frames = 0
    last_stats: tuple[int, ...] | None = None

    # Do not start the clock until data is actually flowing.
    #
    # Closing the serial port resets the board: the CDC control lines are wired
    # to reset on this interface, which is how esptool reboots it. The benchmark
    # firmware then waits ~5 s before streaming so esptool can reach it. Timing
    # from the moment of open therefore counts that dead time as zero
    # throughput, which made repeat measurements read ~411 kB/s against a true
    # ~730. Wait for the first packet, then measure.
    warmup_deadline = time.monotonic() + 15.0
    while time.monotonic() < warmup_deadline:
        chunk = ser.read(8192)
        if not chunk:
            continue
        if any(f.ftype is FrameType.PACKET for f in parser.feed(chunk)):
            break
    else:
        ser.close()
        raise RuntimeError("no packets within 15 s; is the benchmark build flashed?")

    start = time.monotonic()
    end = start + seconds
    idle_reads = 0

    while time.monotonic() < end:
        chunk = ser.read(8192)
        if chunk:
            idle_reads = 0
            frames = parser.feed(chunk)
        else:
            # Nothing for ~0.5 s. A frame may be stalled mid-payload because
            # its tail was discarded; only the caller can break that deadlock.
            idle_reads += 1
            frames = parser.force_resync() if idle_reads >= 10 else []
            if frames:
                idle_reads = 0

        for frame in frames:
            tracker.observe(frame.seq)
            if frame.ftype is FrameType.PACKET:
                packet_frames += 1
                payload_bytes += len(frame.payload)
                framed_bytes += len(frame.payload) + 10
            elif frame.ftype is FrameType.STATS:
                if len(frame.payload) >= _STATS_STRUCT.size:
                    last_stats = _STATS_STRUCT.unpack(
                        frame.payload[: _STATS_STRUCT.size]
                    )

    elapsed = time.monotonic() - start
    ser.close()

    result: dict = {
        "elapsed_s": round(elapsed, 3),
        "packet_frames": packet_frames,
        "payload_bytes": payload_bytes,
        "payload_kB_per_s": round(payload_bytes / elapsed / 1000, 1),
        "wire_kB_per_s": round(framed_bytes / elapsed / 1000, 1),
        "frames_per_s": round(packet_frames / elapsed, 1),
        "frames_missed_host_side": tracker.total_missed,
        "resyncs": parser.resync_count,
        "bytes_discarded": parser.bytes_discarded,
    }
    if last_stats:
        result.update(
            {f"fw_{name}": value for name, value in zip(_STATS_FIELDS, last_stats)}
        )
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="ESP32-C6 USB throughput benchmark")
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--seconds", type=float, default=20.0)
    args = ap.parse_args()

    for key, value in run(args.port, args.seconds).items():
        print(f"{key:28s} {value}")


if __name__ == "__main__":
    main()
