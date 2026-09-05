#!/usr/bin/env python3
"""Wireshark extcap plugin: ESP32-C6 as an IEEE 802.15.4 capture interface.

Wireshark drives an extcap program through query modes and one capture mode.
It asks what interfaces exist, what link types and options each supports, then
runs it with a named pipe to write a pcap stream into.

Only the 802.15.4 interface is advertised. Wi-Fi and BLE come in later
milestones and are deliberately absent rather than present-and-broken: an
interface that appears in Wireshark and then fails is worse than one that is
not there yet.

Install with extcap/install.ps1, which copies this and its .bat launcher into
%APPDATA%\\Wireshark\\extcap.
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback

# Allow running straight from the repository as well as from the install
# directory, where the package sits alongside this file.
_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (
    os.path.join(_HERE, "..", "host", "src"),
    os.path.join(_HERE, "lib"),
):
    _candidate = os.path.abspath(_candidate)
    if os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, _candidate)

INTERFACE = "esp32c6-802154"
DISPLAY = "ESP32-C6 IEEE 802.15.4 (Zigbee/Thread)"
DLT_NUMBER = 283
DLT_NAME = "IEEE802_15_4_TAP"

CHANNEL_MIN = 11
CHANNEL_MAX = 26
DEFAULT_CHANNEL = 11
DEFAULT_PORT = "COM3" if os.name == "nt" else "/dev/ttyACM0"


def channel_frequency_mhz(channel: int) -> int:
    """2.4 GHz O-QPSK: channel 11 is 2405 MHz, 5 MHz apart."""
    return 2405 + 5 * (channel - CHANNEL_MIN)


def print_interfaces() -> None:
    print("extcap {version=0.1.0}"
          "{help=https://github.com/}"
          "{display=ESP32-C6 Sniffer}")
    print(f"interface {{value={INTERFACE}}}{{display={DISPLAY}}}")


def print_dlts() -> None:
    print(f"dlt {{number={DLT_NUMBER}}}{{name={DLT_NAME}}}"
          f"{{display=IEEE 802.15.4 with TAP pseudo-header}}")


def print_config() -> None:
    # Note there is deliberately no baud rate option. This is a USB CDC
    # virtual port with no physical line rate, so the setting is discarded.
    # Other projects expose one, inherited from bridge-chip designs, which
    # misleads anyone who tries to tune it.
    print(f"arg {{number=0}}{{call=--port}}{{display=Serial port}}"
          f"{{type=string}}{{default={DEFAULT_PORT}}}"
          f"{{tooltip=Serial port the board enumerates as}}"
          f"{{required=true}}")
    print(f"arg {{number=1}}{{call=--channel}}{{display=Channel}}"
          f"{{type=selector}}{{default={DEFAULT_CHANNEL}}}"
          f"{{tooltip=IEEE 802.15.4 channel. Zigbee commonly uses "
          f"11, 15, 20 and 25}}")
    for channel in range(CHANNEL_MIN, CHANNEL_MAX + 1):
        print(f"value {{arg=1}}{{value={channel}}}"
              f"{{display={channel} ({channel_frequency_mhz(channel)} MHz)}}")
    print("arg {number=2}{call=--antenna}{display=Antenna}"
          "{type=selector}{default=0}"
          "{tooltip=External needs a U.FL antenna fitted. Community "
          "measurements put it 5-10 dB ahead of the onboard one}")
    print("value {arg=2}{value=0}{display=Onboard ceramic}")
    print("value {arg=2}{value=1}{display=External U.FL}")


def do_capture(fifo: str, port: str, channel: int, antenna: int) -> int:
    from esp32c6_sniffer.capture import CaptureSession
    from esp32c6_sniffer.control import Antenna
    from esp32c6_sniffer.pcap import PcapWriter
    from esp32c6_sniffer.tap import LINKTYPE_IEEE802_15_4_TAP

    with open(fifo, "wb") as pipe:
        writer = PcapWriter(pipe, LINKTYPE_IEEE802_15_4_TAP)
        writer.flush()
        with CaptureSession(port, channel=channel,
                            antenna=Antenna(antenna)) as session:
            for record, timestamp in session.records():
                writer.write_packet(record, timestamp)
                # Flush per packet or Wireshark shows nothing until the
                # buffer fills, which looks like a broken capture.
                writer.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-version", nargs="?", default=None)
    parser.add_argument("--extcap-interface", default=None)
    parser.add_argument("--extcap-reload-option", default=None)
    parser.add_argument("--capture", action="store_true")
    parser.add_argument("--fifo", default=None)
    parser.add_argument("--port", default=DEFAULT_PORT)
    parser.add_argument("--channel", type=int, default=DEFAULT_CHANNEL)
    parser.add_argument("--antenna", type=int, default=0)
    args, _unknown = parser.parse_known_args(argv)

    if args.extcap_interfaces:
        print_interfaces()
        return 0

    if args.extcap_interface is not None and args.extcap_interface != INTERFACE:
        sys.stderr.write(f"unknown interface: {args.extcap_interface}\n")
        return 1

    if args.extcap_dlts:
        print_dlts()
        return 0
    if args.extcap_config:
        print_config()
        return 0
    if args.capture:
        if not args.fifo:
            sys.stderr.write("--capture requires --fifo\n")
            return 1
        if not CHANNEL_MIN <= args.channel <= CHANNEL_MAX:
            sys.stderr.write(
                f"channel {args.channel} outside {CHANNEL_MIN}-{CHANNEL_MAX}\n"
            )
            return 1
        return do_capture(args.fifo, args.port, args.channel, args.antenna)

    # No recognised mode. Listing interfaces is the safest default, since that
    # is what Wireshark asks for first.
    print_interfaces()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (BrokenPipeError, KeyboardInterrupt):
        # Wireshark stops a capture by closing the pipe. Normal, not an error.
        sys.exit(0)
    except Exception:
        # Wireshark surfaces stderr to the user, so a silent failure here would
        # be untraceable from the GUI.
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
