#!/usr/bin/env python3
"""Wireshark extcap plugin: ESP32-C6 as a capture interface.

Wireshark drives an extcap program through query modes and one capture mode.
It asks what interfaces exist, what link types and options each supports, then
runs it with a named pipe to write a pcap stream into.

Two interfaces are advertised, one per radio: IEEE 802.15.4 for Zigbee and
Thread, and 2.4 GHz Wi-Fi. They cannot run at once -- the C6 has a single
2.4 GHz front end -- but Wireshark treats them as separate interfaces, so
starting one while the other captures will simply fail to open the port. BLE
comes in a later milestone and is deliberately absent rather than
present-and-broken: an interface that appears in Wireshark and then fails is
worse than one that is not there yet.

Toolbar channel values carry a one-letter radio prefix ("z25", "w6") rather
than a bare number. Channels 11 to 14 exist in BOTH radios and mean different
frequencies, so a bare number in a shared toolbar is ambiguous. The prefix
makes a mis-click detectable instead of silently retuning to the wrong band.

TOOLBAR CONTROLS
----------------
Wireshark can give an extcap a toolbar, driven by a pair of control pipes. We
use it for three things:

* A channel selector that retunes the radio MID-CAPTURE, with no restart. This
  is coherent for us specifically because we emit IEEE802_15_4_TAP, where the
  channel is a per-packet field, so a retuned capture stays self-describing.
  A sniffer whose channel lived in a file-level header could not do this.
* An antenna toggle, which makes the measured +6.0 dB difference between the
  onboard and external antennas a live A/B on the same traffic rather than a
  comparison across two runs where the traffic itself has changed.
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

WIFI_INTERFACE = "esp32c6-wifi"
WIFI_DISPLAY = "ESP32-C6 Wi-Fi 2.4 GHz (802.11)"
WIFI_DLT_NUMBER = 127
WIFI_DLT_NAME = "IEEE802_11_RADIOTAP"

CHANNEL_MIN = 11
CHANNEL_MAX = 26
DEFAULT_CHANNEL = 11

WIFI_CHANNEL_MIN = 1
WIFI_CHANNEL_MAX = 14
WIFI_DEFAULT_CHANNEL = 6

# A busy 802.11 channel produces far more than the USB link carries, so the
# snapshot length is not a tuning knob but a requirement. What it discards is
# encrypted payload; the headers worth having are at the front.
WIFI_DEFAULT_SNAPLEN = 256
WIFI_MAX_SNAPLEN = 512

# Channel sets for hopping. 1/6/11 are the non-overlapping set in the UK.
HOP_SETS = {
    0: None,
    1: (1, 6, 11),
    2: tuple(range(1, 14)),
}

DEFAULT_PORT = "COM3" if os.name == "nt" else "/dev/ttyACM0"

INTERFACES = {
    INTERFACE: {
        "display": DISPLAY,
        "dlt": DLT_NUMBER,
        "dlt_name": DLT_NAME,
        "dlt_display": "IEEE 802.15.4 with TAP pseudo-header",
        "band": "802.15.4",
        "prefix": "z",
        "min": CHANNEL_MIN,
        "max": CHANNEL_MAX,
        "default": DEFAULT_CHANNEL,
    },
    WIFI_INTERFACE: {
        "display": WIFI_DISPLAY,
        "dlt": WIFI_DLT_NUMBER,
        "dlt_name": WIFI_DLT_NAME,
        "dlt_display": "IEEE 802.11 with radiotap header",
        "band": "Wi-Fi",
        "prefix": "w",
        "min": WIFI_CHANNEL_MIN,
        "max": WIFI_CHANNEL_MAX,
        "default": WIFI_DEFAULT_CHANNEL,
    },
}

# Toolbar control numbers. Ordering in the toolbar follows these.
CTRL_ARG_CHANNEL = 0
CTRL_ARG_ANTENNA = 1
CTRL_ARG_LOGGER = 2
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


def wifi_frequency_mhz(channel: int) -> int:
    """802.11b/g/n: channel 1 is 2412 MHz, 5 MHz apart, with 14 an exception."""
    if channel == 14:
        return 2484
    return 2412 + 5 * (channel - 1)


def channel_label(interface: str, channel: int) -> str:
    if interface == WIFI_INTERFACE:
        return f"{channel} ({wifi_frequency_mhz(channel)} MHz)"
    return f"{channel} ({channel_frequency_mhz(channel)} MHz)"


def channel_token(interface: str, channel: int) -> str:
    """Toolbar value for a channel, prefixed with its radio."""
    return f"{INTERFACES[interface]['prefix']}{channel}"


def parse_channel_token(interface: str, text: str) -> int:
    """Reads a toolbar channel value back, rejecting the other radio's.

    Raises ValueError with a message worth showing the user.
    """
    text = text.strip()
    expected = INTERFACES[interface]["prefix"]
    if text and text[0].isalpha():
        prefix, number = text[0], text[1:]
        if prefix != expected:
            other = next(
                name for name, spec in INTERFACES.items()
                if spec["prefix"] == prefix
            )
            raise ValueError(
                f"that channel belongs to {INTERFACES[other]['display']}, "
                f"not this capture"
            )
    else:
        number = text
    channel = int(number)
    spec = INTERFACES[interface]
    if not spec["min"] <= channel <= spec["max"]:
        raise ValueError(
            f"channel {channel} outside {spec['min']}-{spec['max']}"
        )
    return channel


def print_interfaces(selected: str | None = None) -> None:
    # The control bitfield must appear BOTH here and on the interface line.
    # Declaring controls only in --extcap-config does not make Wireshark
    # create the pipes, and the failure is silent.
    print(f"extcap {{version=0.3.0}}{{display=ESP32-C6 Sniffer}}"
          f"{{control={CONTROL_BITS}}}")
    for name, spec in INTERFACES.items():
        print(f"interface {{value={name}}}{{display={spec['display']}}}"
              f"{{control={CONTROL_BITS}}}")
    print(f"control {{number={CTRL_ARG_CHANNEL}}}{{type=selector}}"
          f"{{display=Channel}}"
          f"{{tooltip=Retunes the radio without restarting the capture}}")
    # When Wireshark names the interface, offer only that radio's channels.
    # Otherwise offer both, which is why the values are prefixed: 11 to 14
    # exist in both radios and mean different frequencies.
    shown = [selected] if selected in INTERFACES else list(INTERFACES)
    for name in shown:
        spec = INTERFACES[name]
        band = "" if len(shown) == 1 else f"{spec['band']} "
        for channel in range(spec["min"], spec["max"] + 1):
            print(f"value {{control={CTRL_ARG_CHANNEL}}}"
                  f"{{value={channel_token(name, channel)}}}"
                  f"{{display={band}{channel_label(name, channel)}}}")
    print(f"control {{number={CTRL_ARG_ANTENNA}}}{{type=boolean}}"
          f"{{display=External antenna}}{{default=false}}"
          f"{{tooltip=Switch antenna without restarting. Measured +6.0 dB for "
          f"external on this board, so this is a live A/B on the same traffic}}")
    print(f"control {{number={CTRL_ARG_LOGGER}}}{{type=button}}{{role=logger}}"
          f"{{display=Log}}{{tooltip=Frame counts and drop counters}}")


def print_dlts(interface: str) -> None:
    spec = INTERFACES[interface]
    print(f"dlt {{number={spec['dlt']}}}{{name={spec['dlt_name']}}}"
          f"{{display={spec['dlt_display']}}}")


def print_config(interface: str) -> None:
    spec = INTERFACES[interface]
    # No baud rate option. This is a USB CDC virtual port with no physical line
    # rate, so the setting is discarded; other projects expose one inherited
    # from bridge-chip designs, which misleads anyone who tries to tune it.
    print(f"arg {{number=0}}{{call=--port}}{{display=Serial port}}"
          f"{{type=string}}{{default={DEFAULT_PORT}}}"
          f"{{tooltip=Serial port the board enumerates as}}{{required=true}}")
    hint = (
        "Wi-Fi in the UK mostly sits on 1, 6 and 11"
        if interface == WIFI_INTERFACE
        else "Zigbee commonly uses 11, 15, 20 and 25"
    )
    print(f"arg {{number=1}}{{call=--channel}}{{display=Channel}}"
          f"{{type=selector}}{{default={spec['default']}}}"
          f"{{tooltip=Starting channel. Also changeable mid-capture from the "
          f"toolbar. {hint}}}")
    for channel in range(spec["min"], spec["max"] + 1):
        print(f"value {{arg=1}}{{value={channel}}}"
              f"{{display={channel_label(interface, channel)}}}")
    print("arg {number=2}{call=--antenna}{display=Antenna}"
          "{type=selector}{default=0}"
          "{tooltip=External needs a U.FL antenna fitted. Measured +6.0 dB "
          "over the onboard one on this board}")
    print("value {arg=2}{value=0}{display=Onboard ceramic}")
    print("value {arg=2}{value=1}{display=External U.FL}")

    if interface != WIFI_INTERFACE:
        return

    # Wi-Fi only. A busy 802.11 channel produces roughly 25x what the USB link
    # carries, so both of these are throughput controls, not preferences.
    print(f"arg {{number=3}}{{call=--snaplen}}{{display=Snapshot length}}"
          f"{{type=integer}}{{range=64,{WIFI_MAX_SNAPLEN}}}"
          f"{{default={WIFI_DEFAULT_SNAPLEN}}}"
          f"{{tooltip=Bytes kept per frame. What is discarded is encrypted "
          f"payload; the headers worth having are at the front}}")
    print("arg {number=4}{call=--filter}{display=Frame types}"
          "{type=selector}{default=5}"
          "{tooltip=Control frames are the most numerous and the least "
          "informative, so dropping them buys link budget cheaply}")
    print("value {arg=4}{value=5}{display=Management and data (recommended)}")
    print("value {arg=4}{value=15}{display=Everything, including control}")
    print("value {arg=4}{value=1}{display=Management only (beacons, probes)}")
    print("arg {number=5}{call=--hop}{display=Channel hop}"
          "{type=selector}{default=0}"
          "{tooltip=Sweeps channels during the capture. Each frame carries its "
          "own channel in radiotap, so a hopped capture stays self-describing. "
          "You will miss whatever lands while the radio is elsewhere}")
    print("value {arg=5}{value=0}{display=Off, stay on one channel}")
    print("value {arg=5}{value=1}{display=1, 6, 11 (non-overlapping)}")
    print("value {arg=5}{value=2}{display=All channels, 1-13}")
    print("arg {number=6}{call=--hop-dwell}{display=Hop dwell (ms)}"
          "{type=integer}{range=100,10000}{default=500}"
          "{tooltip=Time on each channel. A beacon interval is about 100 ms, "
          "so below roughly 300 ms you will miss beacons}")


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
               control_in: str | None, control_out: str | None,
               interface: str = INTERFACE, snaplen: int | None = None,
               frame_filter: int | None = None, hop: int = 0,
               hop_dwell_ms: int = 500) -> int:
    from esp32c6_sniffer.capture import CaptureSession
    from esp32c6_sniffer.control import Antenna, FrameFilter, Radio

    from esp32c6_sniffer.pcap import PcapWriter

    radio = Radio.WIFI if interface == WIFI_INTERFACE else Radio.IEEE802154
    # Snapshot length and frame filter apply to Wi-Fi only; sending them on an
    # 802.15.4 capture would be silently ignored, which is worse than not
    # sending them.
    wifi = radio is Radio.WIFI
    session_snaplen = snaplen if wifi else None
    session_filter = (
        FrameFilter(frame_filter) if wifi and frame_filter else None
    )
    hop_channels = HOP_SETS.get(hop) if wifi else None

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
            if cmd == CTRL_CMD_SET and arg == CTRL_ARG_ANTENNA:
                # Boolean controls carry a raw 0/1 byte, not the ASCII digit.
                external = bool(payload and payload[0])
                try:
                    session.request_antenna(1 if external else 0)
                    log(f"antenna -> {'external' if external else 'onboard'}")
                except ValueError as exc:
                    log(f"bad antenna value: {exc}")
                continue
            if cmd == CTRL_CMD_SET and arg == CTRL_ARG_CHANNEL:
                try:
                    wanted = parse_channel_token(
                        interface, payload.decode("utf-8", "ignore")
                    )
                    session.request_channel(wanted)
                    log(f"retuning to channel {wanted}")
                    control_write(fp_out, CTRL_ARG_NONE, CTRL_CMD_STATUSBAR,
                                  f"ESP32-C6: channel {wanted}".encode())
                except (ValueError, UnicodeDecodeError) as exc:
                    # Selecting the other radio's channel lands here. Say so
                    # rather than silently ignoring it.
                    log(f"channel not applied: {exc}")

    # Order matters: capture fifo, then control-out, then control-in. Both
    # reference implementations do this and the pipes can block otherwise.
    with open(fifo, "wb") as pipe:
        # Link type follows the radio, so the header matches what records()
        # actually emits rather than whichever one was written first.
        session_linktype = (
            WIFI_DLT_NUMBER if radio is Radio.WIFI else DLT_NUMBER
        )
        writer = PcapWriter(pipe, session_linktype)
        writer.flush()

        if control_out:
            fp_out = open(control_out, "wb", 0)
        fp_in = open(control_in, "rb", 0) if control_in else None

        with CaptureSession(port, channel=channel,
                            antenna=Antenna(antenna),
                            radio=radio,
                            snaplen=session_snaplen,
                            frame_filter=session_filter) as session:
            thread = None
            if fp_in is not None:
                thread = threading.Thread(target=reader, args=(fp_in, session),
                                          daemon=True)
                thread.start()
            else:
                state["initialized"] = True   # no toolbar; nothing to wait for

            if hop_channels:
                # request_channel() only sets a flag; the capture loop owns the
                # serial port and applies it between reads, so hopping from a
                # second thread cannot interleave bytes mid-frame.
                def hopper() -> None:
                    index = 0
                    while state["running"]:
                        time.sleep(hop_dwell_ms / 1000.0)
                        if not state["running"]:
                            return
                        index = (index + 1) % len(hop_channels)
                        try:
                            session.request_channel(hop_channels[index])
                        except ValueError as exc:
                            log(f"hop skipped: {exc}")

                threading.Thread(target=hopper, daemon=True).start()
                log(f"hopping {list(hop_channels)} every {hop_dwell_ms} ms")

            next_report = time.monotonic() + 1.0
            try:
                for record, timestamp, original_len in session.records():
                    writer.write_packet(record, timestamp,
                                        original_length=original_len)
                    # Flush per packet or Wireshark shows nothing until the
                    # buffer fills, which looks like a broken capture.
                    writer.flush()
                    if not state["running"]:
                        break
                    now = time.monotonic()
                    if now >= next_report:
                        next_report = now + 1.0
                        s = session.stats
                        extra = ""
                        if s.fw_recoveries:
                            # A workaround for a fault that is not ours, so it
                            # is surfaced rather than hidden.
                            extra += (f", receiver rebuilt {s.fw_recoveries}x "
                                      f"after going deaf")
                        if s.fw_stalled_seconds:
                            extra += (f", no frames for {s.fw_stalled_seconds}s"
                                      f" -- if this persists the receiver has "
                                      f"latched deaf; stop the capture and run "
                                      f"tools/wifi_survey.py --recover")
                        if s.fw_frames_truncated:
                            # Not loss: the snapshot length is deliberate, and
                            # what it cuts is encrypted payload.
                            extra += (f", {s.fw_frames_truncated} truncated")
                        if s.lossless:
                            log(f"ch {session._channel}: {s.frames} frames, "
                                f"no loss{extra}")
                        else:
                            log(f"ch {session._channel}: {s.frames} frames, "
                                f"LOSS gaps={s.sequence_gaps} "
                                f"isr={s.fw_isr_queue_full} "
                                f"link={s.fw_link_rejected}{extra}")
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
    # No default here: it depends on which interface was named, and a fixed
    # 802.15.4 default would be an invalid Wi-Fi channel.
    parser.add_argument("--channel", type=int, default=None)
    parser.add_argument("--antenna", type=int, default=0)
    parser.add_argument("--snaplen", type=int, default=None)
    parser.add_argument("--filter", dest="frame_filter", type=int, default=None)
    parser.add_argument("--hop", type=int, default=0)
    parser.add_argument("--hop-dwell", dest="hop_dwell", type=int, default=500)
    args, _unknown = parser.parse_known_args(argv)

    if args.extcap_interfaces:
        print_interfaces(args.extcap_interface)
        return 0

    if (args.extcap_interface is not None
            and args.extcap_interface not in INTERFACES):
        sys.stderr.write(f"unknown interface: {args.extcap_interface}\n")
        return 1

    # Every remaining mode is interface-specific. Defaulting to 802.15.4
    # keeps a bare invocation working, as it did before Wi-Fi existed.
    interface = args.extcap_interface or INTERFACE
    spec = INTERFACES[interface]

    if args.extcap_dlts:
        print_dlts(interface)
        return 0
    if args.extcap_config:
        print_config(interface)
        return 0
    if args.capture:
        if not args.fifo:
            sys.stderr.write("--capture requires --fifo\n")
            return 1
        channel = args.channel if args.channel is not None else spec["default"]
        if not spec["min"] <= channel <= spec["max"]:
            sys.stderr.write(
                f"channel {channel} outside {spec['min']}-{spec['max']}\n"
            )
            return 1
        if args.snaplen is not None and not 1 <= args.snaplen <= WIFI_MAX_SNAPLEN:
            sys.stderr.write(
                f"snaplen {args.snaplen} outside 1-{WIFI_MAX_SNAPLEN}" + os.linesep
            )
            return 1
        if args.hop not in HOP_SETS:
            sys.stderr.write(f"unknown hop set {args.hop}" + os.linesep)
            return 1
        return do_capture(args.fifo, args.port, channel, args.antenna,
                          args.extcap_control_in, args.extcap_control_out,
                          interface, args.snaplen, args.frame_filter,
                          args.hop, args.hop_dwell)

    print_interfaces(args.extcap_interface)
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
