"""Asking the board which access points it can hear.

A scan is not a capture: the board's Wi-Fi driver sweeps the channels itself
and reports what it found, which takes a few seconds and needs the port to
itself. It answers the question a capture cannot, because a capture is
single-channel and shows only what is transmitting during the window.

This lives in the library rather than in a tool because three callers wanted
it -- the survey, the self-test, and the Wireshark plugin's channel list --
and two of them had grown their own copy.

The scan is PASSIVE by default: the radio listens for beacons and transmits
nothing. Active scanning sends probe requests, which is a transmission and
therefore off unless asked for.
"""

from __future__ import annotations

import time

import serial

from .apscan import AccessPoint, parse_ap_record
from .control import Command, Radio, decode_reply, encode_command
from .framing import FrameType
from .parser import StreamParser
from .recovery import ensure_wifi_ready

#: How long to wait for the board to settle after selecting the radio. The
#: driver reinitialises, and commands sent during that are answered late.
RADIO_SETTLE_S = 3.0

#: A full passive sweep of 1-13 takes a few seconds; this is the ceiling
#: before giving up rather than the expected duration.
DEFAULT_TIMEOUT_S = 20.0


def scan_access_points(
    port: str,
    *,
    active: bool = False,
    timeout: float = DEFAULT_TIMEOUT_S,
    settle: float = RADIO_SETTLE_S,
) -> list[AccessPoint]:
    """Scans for access points, opening and closing the port itself.

    Raises TimeoutError if the board never reports the scan complete, and
    RuntimeError if it reports a failure. A malformed record is skipped rather
    than fatal: one bad record must not lose the whole scan.

    The completion reply arrives *after* the records, which is what makes the
    list complete rather than merely quiet at that moment -- returning on a
    lull would truncate the results on a slow sweep.
    """
    # Before the port is opened, and not optional. Using the 802.15.4 radio
    # leaves the Wi-Fi receiver deaf until the RF domain is power-gated, and a
    # deaf receiver does not fail a scan -- it completes one and reports no
    # access points at all. Without this the reload button annotated every
    # channel "quiet" on a band with four networks on it.
    if ensure_wifi_ready(port):
        time.sleep(settle)

    handle = serial.Serial(port, 115200, timeout=0.1)
    try:
        try:
            handle.set_buffer_size(rx_size=1 << 20)
        except (AttributeError, OSError):
            pass
        parser = StreamParser()

        handle.write(encode_command(Command.SET_RADIO, int(Radio.WIFI),
                                    radio=Radio.WIFI))
        handle.flush()
        deadline = time.monotonic() + settle
        while time.monotonic() < deadline:
            parser.feed(handle.read(4096))

        handle.write(encode_command(Command.WIFI_SCAN, 1 if active else 0,
                                    radio=Radio.WIFI))
        handle.flush()

        found: list[AccessPoint] = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for frame in parser.feed(handle.read(8192)):
                if frame.ftype is FrameType.AP_RECORD:
                    try:
                        found.append(parse_ap_record(frame.payload))
                    except ValueError:
                        continue
                elif frame.ftype is FrameType.CONTROL_REPLY:
                    reply = decode_reply(frame.payload)
                    if reply["command"] is Command.WIFI_SCAN:
                        if not reply["ok"]:
                            raise RuntimeError(
                                f"scan failed, status {reply['status']}")
                        return found
        raise TimeoutError(f"no scan reply from {port} within {timeout:.0f}s")
    finally:
        handle.close()


def busiest_channels(access_points: list[AccessPoint]) -> dict[int, int]:
    """Access points per channel, for choosing where to point a capture.

    Counting access points is a proxy for traffic, not a measurement of it:
    one busy network beats four idle ones. It is the cheap half of the
    question, and the energy detector answers the other half.
    """
    counts: dict[int, int] = {}
    for ap in access_points:
        counts[ap.channel] = counts.get(ap.channel, 0) + 1
    return counts
