#!/usr/bin/env python3
"""Wireshark extcap plugin: ESP32-C6 as an IEEE 802.15.4 capture interface.

Wireshark drives an extcap program through query modes and one capture mode.
It asks what interfaces exist, what link types and options each supports, then
runs it with a named pipe to write a pcap stream into.

Only the 802.15.4 interface is advertised. Wi-Fi and BLE come in later
milestones and are deliberately absent rather than present-and-broken: an
interface that appears in Wireshark and then fails is worse than one that is
not there yet.

TOOLBAR CONTROLS
----------------
Wireshark can give an extcap a toolbar, driven by a pair of control pipes. We
use it for two things:

* A channel selector that retunes the radio MID-CAPTURE, with no restart. This
  is coherent for us specifically because we emit IEEE802_15_4_TAP, where the
  channel is a per-packet field, so a retuned capture stays self-describing.
  A sniffer whose channel lived in a file-level header could not do this.
* A log window showing frame counts and the board's own drop counters, so
  "did I miss anything?" is answerable at a glance instead of never.

Enable it in Wireshark under View, Interface Toolbars. Note tshark has no
toolbar at all, so nothing essential may live here: the channel is also a
normal option in the interface dialog.

Install with extcap/install.ps1, which copies this and its .bat launcher into
%APPDATA%\\Wireshark\\extcap.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys
import threading
import time
import traceback

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

# Toolbar control numbers. Ordering in the toolbar follows these.
CTRL_ARG_CHANNEL = 0
CTRL_ARG_LOGGER = 1
CTRL_ARG_NONE = 255

# Control commands. Wireshark only ever SENDS 0 and 1; the rest are ours to send.
CTRL_CMD_INITIALIZED = 0
CTRL_CMD_SET = 1
CTRL_CMD_ADD = 2
CTRL_CMD_REMOVE = 3
CTRL_CMD_ENABLE = 4
CTRL_CMD_DISABLE = 5
CTRL_CMD_STATUSBAR = 6
CTRL_CMD_INFORMATION = 7
CTRL_CMD_WARNING = 8
CTRL_CMD_ERROR = 9

# control bitfield: 1 = toolbar messages, 2 = quit messages, 3 = both.
CONTROL_BITS = 3


def channel_frequency_mhz(channel: int) -> int:
    """2.4 GHz O-QPSK: channel 11 is 2405 MHz, 5 MHz apart."""
    return 2405 + 5 * (channel - CHANNEL_MIN)


def print_interfaces() -> None:
    # The control bitfield must appear BOTH here and on the interface line.
    # Declaring controls only in --extcap-config does not make Wireshark
    # create the pipes, and the failure is silent.
    print(f"extcap {{version=0.2.0}}{{display=ESP32-C6 Sniffer}}"
          f"{{control={CONTROL_BITS}}}")
    print(f"interface {{value={INTERFACE}}}{{display={DISPLAY}}}"
          f"{{control={CONTROL_BITS}}}")
    print(f"control {{number={CTRL_ARG_CHANNEL}}}{{type=selector}}"
          f"{{display=Channel}}"
          f"{{tooltip=Retunes the radio without restarting the capture}}")
    for channel in range(CHANNEL_MIN, CHANNEL_MAX + 1):
        print(f"value {{control={CTRL_ARG_CHANNEL}}}{{value={channel}}}"
              f"{{display={channel} ({channel_frequency_mhz(channel)} MHz)}}")
    print(f"control {{number={CTRL_ARG_LOGGER}}}{{type=button}}{{role=logger}}"
          f"{{display=Log}}{{tooltip=Frame counts and drop counters}}")


def print_dlts() -> None:
    print(f"dlt {{number={DLT_NUMBER}}}{{name={DLT_NAME}}}"
          f"{{display=IEEE 802.15.4 with TAP pseudo-header}}")


def print_config() -> None:
    # No baud rate option. This is a USB CDC virtual port with no physical line
    # rate, so the setting is discarded; other projects expose one inherited
    # from bridge-chip designs, which misleads anyone who tries to tune it.
    print(f"arg {{number=0}}{{call=--port}}{{display=Serial port}}"
          f"{{type=string}}{{default={DEFAULT_PORT}}}"
          f"{{tooltip=Serial port the board enumerates as}}{{required=true}}")
    print(f"arg {{number=1}}{{call=--channel}}{{display=Channel}}"
          f"{{type=selector}}{{default={DEFAULT_CHANNEL}}}"
          f"{{tooltip=Starting channel. Also changeable mid-capture from the "
          f"toolbar. Zigbee commonly uses 11, 15, 20 and 25}}")
    for channel in range(CHANNEL_MIN, CHANNEL_MAX + 1):
        print(f"value {{arg=1}}{{value={channel}}}"
              f"{{display={channel} ({channel_frequency_mhz(channel)} MHz)}}")
    print("arg {number=2}{call=--antenna}{display=Antenna}"
          "{type=selector}{default=0}"
          "{tooltip=External needs a U.FL antenna fitted. Measured +6.0 dB "
          "over the onboard one on this board}")
    print("value {arg=2}{value=0}{display=Onboard ceramic}")
    print("value {arg=2}{value=1}{display=External U.FL}")


# --- control pipe framing --------------------------------------------------
#
# Header is 4 bytes: a sync byte ('T' toolbar, 'Q' quit) then a 3-byte length
# in network order, covering the 2-byte toolbar header plus payload. Python
# handles the 3-byte field as a B + H pair, which is exact because messages to
# extcaps cap at 65537 bytes.

def control_read(fp):
    """Returns (control_number, command, payload), or (None, None, None)."""
    try:
        header = fp.read(6)
        if not header or len(header) < 6:
            return None, None, None
        sync, _high, length, arg, cmd = struct.unpack(">sBHBB", header)
        payload = fp.read(length - 2) if length > 2 else b""
        if sync == b"Q":
            return None, None, None
        return arg, cmd, payload
    except (OSError, struct.error):
        return None, None, None


def control_write(fp, arg: int, cmd: int, payload: bytes) -> None:
    if fp is None:
        return
    try:
        fp.write(struct.pack(">sBHBB", b"T", 0, len(payload) + 2, arg, cmd))
        fp.write(payload)
        fp.flush()
    except (OSError, ValueError):
        pass


def do_capture(fifo: str, port: str, channel: int, antenna: int,
               control_in: str | None, control_out: str | None) -> int:
    from esp32c6_sniffer.capture import CaptureSession
    from esp32c6_sniffer.control import Antenna
    from esp32c6_sniffer.pcap import PcapWriter
    from esp32c6_sniffer.tap import LINKTYPE_IEEE802_15_4_TAP

    state = {"initialized": False, "running": True}
    fp_out = None

    def log(text: str) -> None:
        if state["initialized"]:
            control_write(fp_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD,
                          text.encode("utf-8") + b"\n")

    def reader(fp_in, session) -> None:
        """Handles toolbar input. Wireshark sends only Initialized and Set."""
        while state["running"]:
            arg, cmd, payload = control_read(fp_in)
            if arg is None and cmd is None:
                state["running"] = False       # quit, or pipe closed
                return
            if cmd == CTRL_CMD_INITIALIZED:
                # Arrives after Wireshark replays every user-changed control.
                # Writing before this is ignored.
                state["initialized"] = True
                log(f"capture started on channel {session._channel}")
                continue
            if cmd == CTRL_CMD_SET and arg == CTRL_ARG_CHANNEL:
                try:
                    wanted = int(payload.decode("utf-8", "ignore").strip())
                    session.request_channel(wanted)
                    log(f"retuning to channel {wanted}")
                    control_write(fp_out, CTRL_ARG_NONE, CTRL_CMD_STATUSBAR,
                                  f"ESP32-C6: channel {wanted}".encode())
                except (ValueError, UnicodeDecodeError) as exc:
                    log(f"bad channel value: {exc}")

    # Order matters: capture fifo, then control-out, then control-in. Both
    # reference implementations do this and the pipes can block otherwise.
    with open(fifo, "wb") as pipe:
        writer = PcapWriter(pipe, LINKTYPE_IEEE802_15_4_TAP)
        writer.flush()

        if control_out:
            fp_out = open(control_out, "wb", 0)
        fp_in = open(control_in, "rb", 0) if control_in else None

        with CaptureSession(port, channel=channel,
                            antenna=Antenna(antenna)) as session:
            thread = None
            if fp_in is not None:
                thread = threading.Thread(target=reader, args=(fp_in, session),
                                          daemon=True)
                thread.start()
            else:
                state["initialized"] = True   # no toolbar; nothing to wait for

            next_report = time.monotonic() + 1.0
            try:
                for record, timestamp in session.records():
                    writer.write_packet(record, timestamp)
                    # Flush per packet or Wireshark shows nothing until the
                    # buffer fills, which looks like a broken capture.
                    writer.flush()
                    if not state["running"]:
                        break
                    now = time.monotonic()
                    if now >= next_report:
                        next_report = now + 1.0
                        s = session.stats
                        if s.lossless:
                            log(f"ch {session._channel}: {s.frames} frames, "
                                f"no loss")
                        else:
                            log(f"ch {session._channel}: {s.frames} frames, "
                                f"LOSS gaps={s.sequence_gaps} "
                                f"isr={s.fw_isr_queue_full} "
                                f"link={s.fw_link_rejected}")
                            control_write(
                                fp_out, CTRL_ARG_NONE, CTRL_CMD_WARNING,
                                b"ESP32-C6 dropped frames; see the Log button",
                            )
            finally:
                state["running"] = False
                if fp_out is not None:
                    fp_out.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--extcap-interfaces", action="store_true")
    parser.add_argument("--extcap-dlts", action="store_true")
    parser.add_argument("--extcap-config", action="store_true")
    parser.add_argument("--extcap-version", nargs="?", default=None)
    parser.add_argument("--extcap-interface", default=None)
    parser.add_argument("--extcap-reload-option", default=None)
    parser.add_argument("--extcap-control-in", default=None)
    parser.add_argument("--extcap-control-out", default=None)
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
        return do_capture(args.fifo, args.port, args.channel, args.antenna,
                          args.extcap_control_in, args.extcap_control_out)

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
