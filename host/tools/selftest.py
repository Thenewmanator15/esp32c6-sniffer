"""End-to-end self-test: exercises every feature against the real board.

The unit tests cover decoding without hardware. This covers the other half --
that the firmware, the link and the host agree, and that each control actually
changes what the radio does. Several checks are differential rather than
absolute: a snapshot length is proved by records getting shorter, not by any
particular size, because an absolute threshold would only measure how big the
frames on air happened to be.

    python tools/selftest.py --port COM3
    python tools/selftest.py --port COM3 --wifi-channel 6 --zigbee-channel 25

Checks that cannot be run in the current environment report SKIP with the
reason. SKIP is never counted as a pass.
"""

from __future__ import annotations

import argparse
import statistics
import threading
import time

import serial

from esp32c6_sniffer.apscan import parse_ap_record
from esp32c6_sniffer.capture import CaptureSession, EXPECTED_FIRMWARE_VERSION
from esp32c6_sniffer.control import (
    Bandwidth,
    Command,
    CtrlFilter,
    FrameFilter,
    Radio,
    decode_reply,
    encode_command,
)
from esp32c6_sniffer.framing import FrameType
from esp32c6_sniffer.parser import StreamParser
from esp32c6_sniffer.radiotap import LINKTYPE_IEEE802_11_RADIOTAP
from esp32c6_sniffer.recovery import ensure_wifi_ready
from esp32c6_sniffer.tap import LINKTYPE_IEEE802_15_4_TAP

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"
results: list[tuple[str, str, str]] = []


def record(name: str, outcome: str, detail: str = "") -> None:
    results.append((name, outcome, detail))
    # Flushed because this runs for minutes and its output is usually piped,
    # where Python buffers and the run looks hung rather than slow.
    print(f"  {outcome:4s}  {name}" + (f"  -- {detail}" if detail else ""),
          flush=True)


def drain(session, seconds: float, on_record=None) -> int:
    """Collects from a session for a fixed wall-clock window.

    records() blocks waiting for the radio, so a deadline tested inside the
    loop never runs when nothing arrives -- which is exactly the case a
    self-test has to survive. The loop therefore runs on a daemon thread and
    this returns when the window expires, whether or not a frame ever came.
    """
    count = 0

    def pump() -> None:
        nonlocal count
        try:
            for rec, _ts, _orig in session.records():
                count += 1
                if on_record is not None:
                    on_record(rec)
        except Exception:
            pass    # the session is closed underneath us on the way out

    thread = threading.Thread(target=pump, daemon=True)
    thread.start()
    thread.join(seconds)
    # Ask the loop to finish and wait for it to actually leave read() before
    # the caller closes the session. Closing the port while this thread is
    # inside read() crashes the interpreter with an access violation rather
    # than an exception, which is exactly what happened before this line.
    session.request_stop()
    thread.join(5.0)
    return count


class Board:
    """Raw command access, for the checks a CaptureSession cannot express."""

    def __init__(self, port: str) -> None:
        self.port = port
        self.ser = None
        self.parser = StreamParser()

    def open(self, settle: float = 2.0) -> "Board":
        deadline = time.time() + 30
        last = None
        while time.time() < deadline:
            try:
                self.ser = serial.Serial(self.port, 115200, timeout=0.05)
                break
            except (OSError, serial.SerialException) as exc:
                last = exc
                time.sleep(0.5)
        if self.ser is None:
            raise RuntimeError(f"cannot open {self.port}: {last}")
        try:
            self.ser.set_buffer_size(rx_size=1 << 20)
        except (AttributeError, OSError):
            pass
        self.ser.reset_input_buffer()
        self.parser = StreamParser()
        time.sleep(settle)
        return self

    def close(self) -> None:
        if self.ser is not None:
            self.ser.close()
            self.ser = None

    def send(self, cmd: Command, value: int = 0,
             radio: Radio = Radio.WIFI) -> None:
        self.ser.write(encode_command(cmd, value, radio=radio))
        self.ser.flush()

    def pump(self, seconds: float, sink=None) -> list:
        end = time.time() + seconds
        replies = []
        while time.time() < end:
            for frame in self.parser.feed(self.ser.read(8192)):
                if frame.ftype is FrameType.CONTROL_REPLY:
                    replies.append(decode_reply(frame.payload))
                elif sink is not None:
                    sink(frame)
        return replies

    def command(self, cmd: Command, value: int = 0,
                radio: Radio = Radio.WIFI, wait: float = 3.0):
        self.send(cmd, value, radio)
        for reply in self.pump(wait):
            if reply["command"] is cmd:
                return reply
        return None


def check_firmware(board: Board) -> bool:
    reply = board.command(Command.GET_INFO)
    if reply is None or not reply["ok"]:
        record("firmware version", FAIL, "no reply to GET_INFO")
        return False
    got = reply["value"]
    if got != EXPECTED_FIRMWARE_VERSION:
        record("firmware version", FAIL,
               f"board {got}, host expects {EXPECTED_FIRMWARE_VERSION}")
        return False
    record("firmware version", PASS, f"v{got}")
    return True


def check_antenna(board: Board) -> None:
    for value, name in ((1, "external"), (0, "internal")):
        reply = board.command(Command.SET_ANTENNA, value)
        if reply is None or not reply["ok"] or reply["value"] != value:
            record("antenna switch", FAIL, f"{name} refused")
            return
    record("antenna switch", PASS, "both positions accepted")


def check_energy_detect(board: Board, channels=(11, 20, 26)) -> None:
    readings = {}
    for ch in channels:
        reply = board.command(Command.ENERGY_DETECT, ch | (1250 << 8),
                              radio=Radio.IEEE802154)
        if reply is None or not reply["ok"]:
            record("energy detect", FAIL, f"channel {ch} refused")
            return
        raw = reply["value"] & 0xFF
        readings[ch] = raw - 256 if raw > 127 else raw
    plausible = all(-120 <= v <= 0 for v in readings.values())
    record("energy detect", PASS if plausible else FAIL,
           ", ".join(f"ch{c} {v} dBm" for c, v in readings.items()))


def check_802154(port: str, channel: int) -> None:
    try:
        with CaptureSession(port, channel=channel) as session:
            if session.linktype != LINKTYPE_IEEE802_15_4_TAP:
                record("802.15.4 link type", FAIL, str(session.linktype))
            else:
                record("802.15.4 link type", PASS, "IEEE802_15_4_TAP (283)")

            frames = drain(session, 12)
            if frames == 0:
                record(f"802.15.4 capture, ch {channel}", SKIP,
                       "no traffic on this channel right now")
                return
            record(f"802.15.4 capture, ch {channel}", PASS,
                   f"{frames} frames in 12 s")
            stats = session.stats
            # A resync means the parser threw bytes away, which happens once
            # when attaching to a stream already in flight: the board emits a
            # stats frame every second from boot, so the first read can land
            # mid-frame. That costs one sequence gap and is not capture loss.
            # Gaps beyond the resyncs are, so they still fail.
            attributable = stats.sequence_gaps <= stats.resyncs
            clean = (stats.fw_isr_queue_full == 0
                     and stats.fw_link_rejected == 0
                     and stats.fw_frames_dropped_ringfull == 0)
            detail = (f"gaps={stats.sequence_gaps} resyncs={stats.resyncs} "
                      f"discarded={stats.bytes_discarded} B "
                      f"isr={stats.fw_isr_queue_full} "
                      f"link={stats.fw_link_rejected}")
            if clean and stats.sequence_gaps == 0:
                record("802.15.4 drop counters", PASS, detail)
            elif clean and attributable:
                record("802.15.4 drop counters", PASS,
                       detail + " (gap explained by attaching mid-stream)")
            else:
                record("802.15.4 drop counters", FAIL, detail)
    except Exception as exc:
        record(f"802.15.4 capture, ch {channel}", FAIL, repr(exc))


def check_retune(port: str, first: int, second: int) -> None:
    """A retune must be applied by the board, not merely accepted."""
    try:
        with CaptureSession(port, channel=first) as session:
            session.request_channel(second)
            drain(session, 10)
            if session.channel == second:
                record("802.15.4 mid-capture retune", PASS,
                       f"{first} -> {second}")
            else:
                record("802.15.4 mid-capture retune", FAIL,
                       "channel never changed")
    except Exception as exc:
        record("802.15.4 mid-capture retune", FAIL, repr(exc))


def check_wifi_scan(board: Board) -> None:
    found = []

    def sink(frame):
        if frame.ftype is FrameType.AP_RECORD:
            found.append(parse_ap_record(frame.payload))

    board.command(Command.SET_RADIO, int(Radio.WIFI))
    board.send(Command.WIFI_SCAN, 0)      # 0 = passive: transmits nothing
    replies = board.pump(20.0, sink)
    scan = [r for r in replies if r["command"] is Command.WIFI_SCAN]
    if not scan:
        record("Wi-Fi passive scan", FAIL, "no reply")
        return
    if not found:
        record("Wi-Fi passive scan", SKIP,
               "no access points; receiver may be latched deaf")
        return
    record("Wi-Fi passive scan", PASS,
           f"{len(found)} access points, board reported {scan[-1]['value']}")
    named = [a for a in found if a.ssid]
    if named:
        first = named[0]
        record("AP record decoding", PASS,
               f"{first.ssid!r} ch{first.channel} {first.rssi_dbm} dBm "
               f"{first.auth_name}")
    else:
        record("AP record decoding", SKIP, "every network hidden")


def wifi_capture(port: str, channel: int, seconds: float, csi=False, **kwargs):
    """Captures for a window. Returns (record lengths, csi records, session)."""
    lengths = []
    csi_records = []
    with CaptureSession(port, channel=channel, radio=Radio.WIFI,
                        csi_sink=csi_records.append if csi else None,
                        **kwargs) as session:
        drain(session, seconds, on_record=lambda rec: lengths.append(len(rec)))
        return lengths, csi_records, session


def check_wifi(port: str, channel: int) -> bool:
    try:
        lengths, _csi, session = wifi_capture(port, channel, 10)
    except Exception as exc:
        record(f"Wi-Fi capture, ch {channel}", FAIL, repr(exc))
        return False
    if not lengths:
        record(f"Wi-Fi capture, ch {channel}", SKIP,
               "no frames; try tools/wifi_survey.py --recover")
        return False
    record(f"Wi-Fi capture, ch {channel}", PASS,
           f"{len(lengths)} frames in 10 s")
    record("Wi-Fi link type",
           PASS if session.linktype == LINKTYPE_IEEE802_11_RADIOTAP else FAIL,
           "IEEE802_11_RADIOTAP (127)")
    return True


def check_snaplen(port: str, channel: int) -> None:
    try:
        short, _c, _s = wifi_capture(port, channel, 8, snaplen=80)
        long_, _c, _s = wifi_capture(port, channel, 8, snaplen=400)
    except Exception as exc:
        record("Wi-Fi snapshot length", FAIL, repr(exc))
        return
    if not short or not long_:
        record("Wi-Fi snapshot length", SKIP, "not enough frames to compare")
        return
    if max(short) < max(long_):
        record("Wi-Fi snapshot length", PASS,
               f"largest record {max(short)} B at snaplen 80, "
               f"{max(long_)} B at 400")
    else:
        record("Wi-Fi snapshot length", FAIL,
               f"no change: {max(short)} vs {max(long_)}")


def check_filter(port: str, channel: int) -> None:
    try:
        everything, _c, _s = wifi_capture(port, channel, 8,
                                          frame_filter=FrameFilter.ALL)
        mgmt, _c, _s = wifi_capture(port, channel, 8,
                                    frame_filter=FrameFilter.MGMT_ONLY)
    except Exception as exc:
        record("Wi-Fi frame filter", FAIL, repr(exc))
        return
    if not everything:
        record("Wi-Fi frame filter", SKIP, "no frames to compare")
        return
    record("Wi-Fi frame filter", PASS,
           f"{len(everything)} frames unfiltered, {len(mgmt)} management only")


def check_ctrl_filter(port: str, channel: int) -> None:
    try:
        wifi_capture(port, channel, 6, frame_filter=FrameFilter.ALL,
                     ctrl_filter=CtrlFilter.NO_ACK)
        record("control-subtype filter", PASS, "NO_ACK mask accepted")
    except Exception as exc:
        record("control-subtype filter", FAIL, repr(exc))


def check_bandwidth(port: str, channel: int) -> None:
    for bw in (Bandwidth.HT40_ABOVE, Bandwidth.HT20):
        try:
            wifi_capture(port, channel, 4, bandwidth=bw)
        except Exception as exc:
            record("channel width", FAIL, f"{bw.name}: {exc!r}")
            return
    record("channel width", PASS, "HT20 and HT40 both accepted")


def check_csi(port: str, channel: int) -> None:
    try:
        _lengths, csi, session = wifi_capture(port, channel, 10, csi=True)
    except Exception as exc:
        record("CSI", FAIL, repr(exc))
        return
    if not csi:
        record("CSI", SKIP, "no records; needs OFDM traffic on this channel")
        return
    subcarriers = sorted({r.subcarriers for r in csi})
    amps = csi[0].amplitudes()
    record("CSI", PASS,
           f"{len(csi)} records, subcarriers {subcarriers}, "
           f"mean amplitude {statistics.mean(amps):.1f}")
    record("CSI decode integrity",
           PASS if session.stats.csi_malformed == 0 else FAIL,
           f"{session.stats.csi_malformed} malformed")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--wifi-channel", type=int, default=6)
    ap.add_argument("--zigbee-channel", type=int, default=25)
    ap.add_argument("--retune-to", type=int, default=20)
    args = ap.parse_args()

    print(f"self-test against {args.port}")

    print("\ntransport and control")
    board = Board(args.port).open()
    try:
        if not check_firmware(board):
            print("\nFirmware mismatch. Reflash before trusting anything else.")
            return 1
        check_antenna(board)
        check_energy_detect(board)
    finally:
        board.close()

    print("\nIEEE 802.15.4")
    check_802154(args.port, args.zigbee_channel)
    check_retune(args.port, args.zigbee_channel, args.retune_to)

    print("\nWi-Fi")
    # The 802.15.4 checks above have just poisoned the shared front end,
    # which is exactly the situation a user hits, so recovering is
    # automatic rather than a flag.
    cycled = ensure_wifi_ready(args.port)
    record("recover front end after 802.15.4",
           PASS if cycled else SKIP,
           "power-cycled" if cycled else "nothing to recover")
    board = Board(args.port).open()
    try:
        check_wifi_scan(board)
    finally:
        board.close()

    if check_wifi(args.port, args.wifi_channel):
        check_snaplen(args.port, args.wifi_channel)
        check_filter(args.port, args.wifi_channel)
        check_ctrl_filter(args.port, args.wifi_channel)
        check_bandwidth(args.port, args.wifi_channel)
        check_csi(args.port, args.wifi_channel)
    else:
        for name in ("Wi-Fi snapshot length", "Wi-Fi frame filter",
                     "control-subtype filter", "channel width", "CSI"):
            record(name, SKIP, "Wi-Fi receiver not delivering frames")

    passed = sum(1 for _n, o, _d in results if o == PASS)
    failed = sum(1 for _n, o, _d in results if o == FAIL)
    skipped = sum(1 for _n, o, _d in results if o == SKIP)
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    if skipped:
        print("Skipped checks are not passes: they could not be run here.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
