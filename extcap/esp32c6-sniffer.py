#!/usr/bin/env python3
"""Wireshark extcap plugin: ESP32-C6 as a capture interface.

Wireshark drives an extcap program through query modes and one capture mode.
It asks what interfaces exist, what link types and options each supports, then
runs it with a named pipe to write a pcap stream into.

Three interfaces are advertised, one per radio: IEEE 802.15.4 for Zigbee and
Thread, 2.4 GHz Wi-Fi, and Bluetooth LE advertisements. They cannot run at once
-- the C6 has a single 2.4 GHz front end -- but Wireshark treats them as
separate interfaces, so starting one while the other captures will simply fail
to open the port.

The BLE interface offers no channel, because the controller rotates the three
advertising channels itself; asking for one is refused rather than ignored.

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
* An antenna toggle, which makes the measured difference between the
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
import platform
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

BLE_INTERFACE = "esp32c6-ble"
BLE_DISPLAY = "ESP32-C6 Bluetooth LE (advertisements)"
BLE_DLT_NUMBER = 201
BLE_DLT_NAME = "BLUETOOTH_HCI_H4_WITH_PHDR"

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
# Below roughly a beacon interval you start missing the beacons that identify
# the networks; above ten seconds it is barely a sweep.
HOP_DWELL_MIN_MS = 100
HOP_DWELL_MAX_MS = 10000

#: Per radio, because the channel numbers mean different frequencies and
#: the useful subsets are different. 802.15.4 got none of this until now, and
#: it is the radio that needs it most: sixteen channels, no beacons to sweep
#: for, and no way to tell which one a network is on without looking.
#:
#: Keyed by RADIO, and looked up through hop_sets(), never by interface name.
#: Keyed by the C6's names, hopping existed only while it was the one board
#: attached: a second board makes Wireshark name every interface with its
#: port, and the option vanished -- or, for Wi-Fi, was offered and then
#: refused. The nRF54L15 never had it.
HOP_SETS = {
    "wifi": {
        0: None,
        1: (1, 6, 11),
        2: tuple(range(1, 14)),
    },
    "802154": {
        0: None,
        # The four Zigbee "preferred" channels, which is where a Zigbee
        # network almost always sits, so this finds one in a quarter of the
        # time a full sweep takes.
        1: (11, 15, 20, 25),
        2: tuple(range(11, 27)),
        # Half the band each, for two boards: one on each half sweeps all
        # sixteen channels in the time eight take, with no dwell spent twice.
        3: tuple(range(11, 19)),
        4: tuple(range(19, 27)),
    },
}

DEFAULT_PORT = "COM3" if os.name == "nt" else "/dev/ttyACM0"

#: The ESP32-C6's built-in USB-Serial-JTAG. Espressif's vendor id and the
#: product id every C6 presents. Used to find the board rather than assume a
#: port number: this machine has a second USB serial device on COM4, and a
#: default of COM3 is a guess that is wrong as often as it is right.
#:
#: That COM4 device turned out to be the other board in this table.
ESP32C6_USB_VID = 0x303A
ESP32C6_USB_PID = 0x1001

#: Every board this plugin knows, keyed by the USB id it enumerates as.
#:
#: Identity has to be settled here rather than over the wire, because the
#: extcap must list its interfaces before any port is opened -- Wireshark asks
#: what exists while nothing is plugged in, and an interface that appears only
#: once a board is attached cannot be configured in advance. A GET_BOARD
#: command would answer too late to name an interface.
#:
#: `radios` records what the FIRMWARE implements, not what the silicon can do.
#: The nRF54L15 has a BLE radio; it gets a BLE interface when there is firmware
#: behind it and not before.
BOARDS = {
    (ESP32C6_USB_VID, ESP32C6_USB_PID): {
        "id": "esp32c6",
        "display": "ESP32-C6",
        "usb": "303A:1001",
        # Written into the pcapng section header. A capture that describes
        # itself must describe the right board.
        "hardware": "Seeed Studio XIAO ESP32-C6",
        # A USB CDC virtual port with no physical line rate: the setting is
        # discarded, and the dialog deliberately offers no baud option.
        "baud": 115200,
        # Order is load-bearing: it is the order interfaces appear in
        # Wireshark's list, and it reproduces the order the hand-written
        # INTERFACES table used before this was generated.
        "radios": ("802154", "ble", "wifi"),
        # The controller's accept list, loaded before a scan starts.
        "ble_filter": True,
        "ble_periodic": True,
        # An FM8625H RF switch on GPIO3/GPIO14. See firmware/main/board.h.
        "antenna": True,
        "antenna_note": ("External needs a U.FL antenna fitted. Measured "
                         "+13 to +14 dB over the onboard one on this board"),
    },
    (0x2886, 0x0066): {
        "id": "nrf54l15",
        "display": "nRF54L15",
        "usb": "2886:0066",
        "hardware": "Seeed Studio XIAO nRF54L15",
        # A real UART rate here, not a formality. This part has no USB
        # controller, so the host is reached over a UART bridged by the
        # board's SAMD11, and 1 Mbaud is the UARTE's ceiling. The board
        # default of 115200 carries 11.7 kB/s against the ~31 kB/s an
        # 802.15.4 channel can produce. Must match the overlay in
        # the boards/ overlay in nrf54l15-sniffer.
        "baud": 1000000,
        # No Wi-Fi radio exists on this part -- within the nRF54L family a
        # USB device controller and Wi-Fi are both absent. BLE is the
        # controller's own, driven over HCI exactly as the C6's is.
        "radios": ("802154", "ble"),
        # The controller's accept list, loaded before a scan starts.
        # Measured on this board: filtering to one advertiser took a capture
        # from 300 packets across six advertisers to 113 from one, and the
        # wire traffic to 43% of unfiltered.
        "ble_filter": True,
        "ble_periodic": True,
        # The same arrangement as the C6's, found while spiking this board:
        # rfsw_pwr on gpio2.3 powers the switch and rfsw_ctl on gpio2.5
        # selects the antenna, both regulator-boot-on in its devicetree.
        # Which position selects which antenna is not documented anywhere.
        # See https://github.com/Thenewmanator15/nrf54l15-sniffer/blob/main/docs/2026-09-14-nrf54l15-spike.md.
        "antenna": True,
        # Deliberately not the C6's +13 dB figure: that was measured on the
        # C6 and is a property of its switch and antennas, not of this one.
        # Which position selects which antenna is not known here either.
        "antenna_note": ("External needs an IPEX antenna fitted. Which "
                         "position selects which antenna is not yet "
                         "established on this board, and the gain "
                         "difference has not been measured"),
    },
}


def list_comports() -> list:
    """Every serial port pyserial can see, or an empty list.

    Its own function so tests can replace the hardware, and so the two ways
    enumeration can fail -- pyserial missing, pyserial raising -- are handled
    in one place.
    """
    try:
        from serial.tools import list_ports
    except Exception:
        return []
    return list(list_ports.comports())


def find_board_ports() -> list[tuple[str, str]]:
    """(port, board id) for every board we recognise, in enumeration order.

    Returns an empty list rather than raising if pyserial cannot enumerate:
    this must never be the reason a capture fails.

    An unrecognised USB id is skipped rather than guessed at. Guessing
    produces a board whose capabilities are wrong, which is worse than a board
    that is absent: it would be selectable, and every option in its dialog
    would be a promise nothing can keep.
    """
    try:
        ports = list_comports()
    except Exception:
        return []
    found: list[tuple[str, str]] = []
    for port in ports:
        board = BOARDS.get((port.vid, port.pid))
        if board is not None:
            found.append((port.device, board["id"]))
    return found


def default_port(board_id: str | None = None) -> str:
    """The port to offer in the dialog: found, not assumed.

    A hardcoded COM3 is a guess that is wrong as often as it is right. The
    number depends on whatever else the machine has enumerated -- the
    development machine has an unrelated USB serial device that takes COM4,
    and could as easily have taken COM3 -- and on Linux and macOS the name is
    not a COM port at all.

    `board_id` narrows it to that board's own ports. Without it, an nRF's
    dialog would default to whichever board enumerated first, which with a C6
    also attached is a confident wrong answer in a required field: the port of
    a different board entirely.

    Falls back to the platform's usual name when no board is attached, so the
    dialog shows something sensible rather than an empty required field. The
    field stays free text: a selector would be empty, and therefore unusable,
    for anyone configuring the interface before plugging the board in.
    """
    found = find_board_ports()
    if board_id is not None:
        found = [pair for pair in found if pair[1] == board_id]
    return found[0][0] if found else DEFAULT_PORT


#: What each radio is, independent of which board carries it.
#:
#: `title` is the half of the display name that follows the board's name, so
#: that "ESP32-C6" + "IEEE 802.15.4 (Zigbee/Thread)" reproduces the name this
#: plugin has always shown. Changing those strings would move users' saved
#: per-interface options, so they are reproduced exactly rather than rebuilt.
RADIOS = {
    "802154": {
        "title": "IEEE 802.15.4 (Zigbee/Thread)",
        "dlt": DLT_NUMBER,
        "dlt_name": DLT_NAME,
        "dlt_display": "IEEE 802.15.4 with TAP pseudo-header",
        "band": "802.15.4",
        "prefix": "z",
        "min": CHANNEL_MIN,
        "max": CHANNEL_MAX,
        "default": DEFAULT_CHANNEL,
    },
    "ble": {
        "title": "Bluetooth LE (advertisements)",
        "dlt": BLE_DLT_NUMBER,
        "dlt_name": BLE_DLT_NAME,
        "dlt_display": "Bluetooth HCI H4 with direction",
        "band": "BLE",
        "prefix": "b",
        # No channel: the controller rotates the three advertising channels
        # itself, so offering one would be a promise the toolbar cannot keep.
        "min": None,
        "max": None,
        "default": 0,
    },
    "wifi": {
        "title": "Wi-Fi 2.4 GHz (802.11)",
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


def _build_interfaces() -> dict:
    """Every interface this plugin can offer: board x the radios it implements.

    Generated rather than written out, because the combinations multiply with
    each board and a hand-maintained table drifts from the board table beside
    it. Ordering follows BOARDS and then that board's declared radio order, so
    the C6's three keep the positions they had.
    """
    built: dict = {}
    for board in BOARDS.values():
        for radio in board["radios"]:
            spec = dict(RADIOS[radio])
            spec["display"] = f"{board['display']} {spec['title']}"
            spec["board"] = board["id"]
            spec["radio"] = radio
            built[f"{board['id']}-{radio}"] = spec
    return built


INTERFACES = _build_interfaces()


def radio_kind(name: str) -> str:
    """Which RADIO an interface drives, whatever board it belongs to.

    The comparisons this replaced tested the interface name against the C6's,
    so `nrf54l15-ble` fell through to the 802.15.4 branch and a BLE capture
    died asking for channel 0 in the 802.15.4 range. Board-keyed matching had
    already caused the same class of failure in the Wireshark profiles; this
    asks the generated table what the interface is instead of guessing from
    what it is called.

    Takes the port-qualified form too, because that is what Wireshark passes
    once more than one board is attached.
    """
    return INTERFACES[split_interface(name)[0]]["radio"]


def is_wifi(name: str) -> bool:
    return radio_kind(name) == "wifi"


def hop_sets(name: str) -> dict:
    """The hop sets an interface offers, whatever board or port it names.

    {0: None} -- hopping off, and nothing else -- for a radio that cannot hop.
    The dialog, the capture and its validation all ask here, so what Wireshark
    offers is exactly what the capture accepts.
    """
    return HOP_SETS.get(radio_kind(name), {0: None})


def is_ble(name: str) -> bool:
    return radio_kind(name) == "ble"


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
    if is_wifi(interface):
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
    if spec["min"] is None:
        raise ValueError(f"{spec['display']} has no selectable channel")
    if not spec["min"] <= channel <= spec["max"]:
        raise ValueError(
            f"channel {channel} outside {spec['min']}-{spec['max']}"
        )
    return channel


#: Separates the radio from the port in an interface name, when more than one
#: board is attached. Chosen because Wireshark passes interface values through
#: unquoted and this survives that; a space or a colon does not.
PORT_SEPARATOR = "@"


def split_interface(name: str) -> tuple[str, str | None]:
    """Splits "esp32c6-wifi@COM7" into its radio and its board.

    Returns (radio, port), with port None for the plain form. The plain form
    is what a single board gets, so the common case keeps the interface names
    -- and therefore Wireshark's saved per-interface options -- unchanged.
    """
    base, separator, port = name.partition(PORT_SEPARATOR)
    return base, (port if separator else None)


def board_for_interface(name: str) -> dict:
    """The BOARDS entry behind an interface name, qualified or not.

    Takes the qualified form too, because print_config and print_dlts are
    handed whatever Wireshark names them, and that carries the port once more
    than one board is attached.
    """
    radio_name = split_interface(name)[0]
    board_id = INTERFACES[radio_name]["board"]
    for board in BOARDS.values():
        if board["id"] == board_id:
            return board
    raise KeyError(f"no board for interface {name}")


def board_interfaces() -> list[tuple[str, str]]:
    """Every (interface value, display name) to advertise.

    One set per board. Two boards mean two radios can capture AT ONCE, which
    the single shared front end otherwise forbids: Zigbee on one and Wi-Fi on
    the other, correlated in one Wireshark session. That is why names carry
    the port.

    With exactly one board the names stay bare, so nothing that was configured
    before moves -- Wireshark saves capture options against the interface name,
    and renaming one silently drops the snapshot length, channel and filter a
    user had set.

    With no board at all, every board we know is offered bare: Wireshark asks
    what exists before anything is plugged in, and we cannot know which board
    is coming. An interface that materialises only once hardware is attached
    cannot be configured in advance.

    A radio is only ever advertised on a port holding the board that has it.
    Advertising esp32c6-802154 on a port holding an nRF would be selectable
    and would fail on open, which is worse than not offering it.
    """
    found = find_board_ports()
    out: list[tuple[str, str]] = []

    if len(found) <= 1:
        present = {board for _port, board in found}
        for name, spec in INTERFACES.items():
            if present and spec["board"] not in present:
                continue
            out.append((name, spec["display"]))
        return out

    for name, spec in INTERFACES.items():
        for port, board in found:
            if board == spec["board"]:
                out.append((f"{name}{PORT_SEPARATOR}{port}",
                            f"{spec['display']} on {port}"))
    return out


def print_interfaces(selected: str | None = None) -> None:
    # The control bitfield must appear BOTH here and on the interface line.
    # Declaring controls only in --extcap-config does not make Wireshark
    # create the pipes, and the failure is silent.
    print(f"extcap {{version=0.3.0}}{{display=ESP32-C6 Sniffer}}"
          f"{{control={CONTROL_BITS}}}")
    for value, display in board_interfaces():
        print(f"interface {{value={value}}}{{display={display}}}"
              f"{{control={CONTROL_BITS}}}")
    if selected is not None:
        selected = split_interface(selected)[0]
    # When Wireshark names the interface, offer only that radio's channels.
    # Otherwise offer both, which is why the values are prefixed: 11 to 14
    # exist in both radios and mean different frequencies.
    shown = [selected] if selected in INTERFACES else list(INTERFACES)
    tunable = [name for name in shown if INTERFACES[name]["min"] is not None]

    # Declared only when there is something to put in it. BLE has no channel --
    # the controller rotates the three advertising channels itself -- and
    # declaring the control anyway gave a BLE capture an empty Channel dropdown
    # in the toolbar, contradicting the refusal the config path already makes.
    if tunable:
        print(f"control {{number={CTRL_ARG_CHANNEL}}}{{type=selector}}"
              f"{{display=Channel}}"
              f"{{tooltip=Retunes the radio without restarting the capture}}")
        for name in tunable:
            spec = INTERFACES[name]
            band = "" if len(tunable) == 1 else f"{spec['band']} "
            for channel in range(spec["min"], spec["max"] + 1):
                print(f"value {{control={CTRL_ARG_CHANNEL}}}"
                      f"{{value={channel_token(name, channel)}}}"
                      f"{{display={band}{channel_label(name, channel)}}}")
    print(f"control {{number={CTRL_ARG_ANTENNA}}}{{type=boolean}}"
          f"{{display=External antenna}}{{default=false}}"
          f"{{tooltip=Switch antenna without restarting. Measured +13 to +14 dB "
          f"external on this board, so this is a live A/B on the same traffic}}")
    print(f"control {{number={CTRL_ARG_LOGGER}}}{{type=button}}{{role=logger}}"
          f"{{display=Log}}{{tooltip=Frame counts and drop counters}}")


def scanned_channel_labels(interface: str, port: str) -> dict[int, str]:
    """Channel -> suffix describing what a scan just heard there.

    Wireshark asks for this when the reload button beside the Channel option
    is pressed. Annotating each channel with the access points found there
    turns a list of numbers into the actual question -- where is the traffic
    -- without leaving the dialog.

    A scan needs the port to itself and takes several seconds. If it cannot
    run, every channel gets the reason rather than the list coming back empty:
    a dropdown that empties itself because the board was busy would be a worse
    failure than one that is merely not annotated.
    """
    spec = INTERFACES[interface]
    channels = range(spec["min"], spec["max"] + 1)
    try:
        from esp32c6_sniffer.scan import busiest_channels, scan_access_points

        counts = busiest_channels(scan_access_points(port))
    except Exception as exc:
        note = f"  [scan failed: {type(exc).__name__}]"
        return {channel: note for channel in channels}

    labels = {}
    for channel in channels:
        found = counts.get(channel, 0)
        labels[channel] = (
            f"  [{found} network{'s' if found > 1 else ''}]" if found
            else "  [quiet]")
    return labels


def print_dlts(interface: str) -> None:
    spec = INTERFACES[interface]
    print(f"dlt {{number={spec['dlt']}}}{{name={spec['dlt_name']}}}"
          f"{{display={spec['dlt_display']}}}")


def print_config(interface: str, reload_option: str | None = None,
                 port: str | None = None) -> None:
    spec = INTERFACES[split_interface(interface)[0]]
    board = board_for_interface(interface)
    # No baud rate option. This is a USB CDC virtual port with no physical line
    # rate, so the setting is discarded; other projects expose one inherited
    # from bridge-chip designs, which misleads anyone who tries to tune it.
    # The default is looked up each time Wireshark opens this dialog, so a
    # board that moved between runs, or is on a machine that never had a COM3,
    # still shows the right port without anybody editing anything.
    detected = [p for p, b in find_board_ports() if b == board["id"]]
    if detected:
        found_note = f"Found: {', '.join(detected)}. "
    else:
        found_note = ("No board found. Check the cable is data-capable: a "
                      "charge-only one enumerates nothing. ")
    print(f"arg {{number=0}}{{call=--port}}{{display=Serial port}}"
          f"{{type=string}}{{default={default_port(board['id'])}}}"
          f"{{tooltip={found_note}Detected by USB id {board['usb']}, so this is "
          f"filled in for you; change it only if you have more than one "
          f"board}}{{required=true}}")
    if spec["min"] is not None:
        hint = (
            "Wi-Fi in the UK mostly sits on 1, 6 and 11"
            if is_wifi(interface)
            else "Zigbee commonly uses 11, 15, 20 and 25"
        )
        # Reloadable on Wi-Fi only, where a scan can say which channels have
        # networks on them. On 802.15.4 the radio has no equivalent -- it can
        # measure energy, but that is the spectrum tool's job and it does not
        # belong behind a dropdown that blocks the dialog while it runs.
        reload_note = ""
        if is_wifi(interface):
            reload_note = ("{reload=true}{placeholder=Reload to scan for "
                           "networks}")
        print(f"arg {{number=1}}{{call=--channel}}{{display=Channel}}"
              f"{{type=selector}}{{default={spec['default']}}}{reload_note}"
              f"{{tooltip=Starting channel. Also changeable mid-capture from "
              f"the toolbar. {hint}}}")
        # Wireshark asks for a reload by calling --extcap-config WITH
        # --extcap-reload-option, naming the option without its dashes, and
        # expects the whole configuration back with that one refreshed. It is
        # not a separate mode; treating it as one printed a bare value list
        # that Wireshark had not asked for.
        scanned = {}
        if reload_option == "channel" and is_wifi(interface):
            scanned = scanned_channel_labels(interface, port or default_port())
        for channel in range(spec["min"], spec["max"] + 1):
            print(f"value {{arg=1}}{{value={channel}}}"
                  f"{{display={channel_label(interface, channel)}"
                  f"{scanned.get(channel, '')}}}")
    # Only where there is a switch to throw. A selector on a board with one
    # hardwired antenna would look like a setting, be set, and change nothing.
    if board["antenna"]:
        print(f"arg {{number=2}}{{call=--antenna}}{{display=Antenna}}"
              f"{{type=selector}}{{default=0}}"
              f"{{tooltip={board['antenna_note']}}}")
        print("value {arg=2}{value=0}{display=Onboard ceramic}")
        print("value {arg=2}{value=1}{display=External U.FL}")

    if interface == INTERFACE:
        print("arg {number=3}{call=--keys}{display=Zigbee key file}"
              "{type=fileselect}{fileext=Key files (*.txt)}"
              "{tooltip=Records Zigbee network keys IN the capture, in a "
              "Decryption Secrets Block. Wireshark shows the block but does "
              "NOT decrypt from it: no dissector consumes the Zigbee secret "
              "types, so the key still has to go in Wireshark's own table. "
              "The block travels with the file for other tools, and for if "
              "that changes. One key per line, 32 hex digits, optionally "
              "prefixed nwk or aps. For a network you own}")
        print("arg {number=4}{call=--thread}{display=Thread credentials}"
              "{type=fileselect}{fileext=Credential files (*.txt)}"
              "{tooltip=A file holding your border router's operational "
              "dataset, or a bare 32-hex network key. Thread encrypts at the "
              "MAC layer, and its key cannot ride inside a capture -- "
              "Wireshark has no 802.15.4 secrets type -- so this INSTALLS it "
              "into Wireshark's own key table, for this profile and the root. "
              "A dataset also carries the channel, and the capture moves to "
              "it, because the wrong channel gives an empty capture that "
              "looks exactly like a wrong key. For a network you own}")

    if radio_kind(interface) == "802154":
        # Every board's 802.15.4 interface, alone or port-qualified. The key
        # and credential options above are still the C6's alone.
        #
        # 802.15.4 needs this more than Wi-Fi does. Wi-Fi has beacons every
        # 100 ms on a handful of channels, so a survey finds the traffic in
        # seconds. Here there are sixteen channels, nothing announces itself,
        # and a quiet capture is indistinguishable from the wrong channel:
        # measured on this bench, channel 11 gave 2 frames in 15 s while 25
        # gave 135.
        print("arg {number=5}{call=--hop}{display=Channel hop}"
              "{type=selector}{default=0}"
              "{group=Sweeping}{tooltip=Sweeps channels during the capture. The channel is a "
              "per-frame field in this link type, so a hopped capture stays "
              "self-describing. You will miss whatever lands while the radio "
              "is elsewhere}")
        print("value {arg=5}{value=0}{display=Off, stay on one channel}")
        print("value {arg=5}{value=1}"
              "{display=11, 15, 20, 25 (Zigbee preferred)}")
        print("value {arg=5}{value=2}{display=All channels, 11-26}")
        print("value {arg=5}{value=3}"
              "{display=Channels 11-18 (half the band: put a second board on 19-26)}")
        print("value {arg=5}{value=4}"
              "{display=Channels 19-26 (half the band: put a second board on 11-18)}")
        print("arg {number=6}{call=--hop-dwell}{display=Hop dwell (ms)}"
              f"{{type=integer}}{{range={HOP_DWELL_MIN_MS},{HOP_DWELL_MAX_MS}}}"
              f"{{default=2000}}"
              "{group=Sweeping}{tooltip=Time on each channel. Longer than the Wi-Fi default: "
              "there are no beacons to catch, so the dwell has to be long "
              "enough for ordinary traffic to happen}")

    if is_ble(interface):
        print("arg {number=3}{call=--ble-interval}{display=Scan interval (ms)}"
              "{type=integer}{range=10,10240}{default=60}"
              "{tooltip=How often the controller starts a scan window}")
        print("arg {number=4}{call=--ble-window}{display=Scan window (ms)}"
              "{type=integer}{range=10,10240}{default=60}"
              "{tooltip=How long it listens each time. Equal to the interval "
              "means continuous listening, which is what a sniffer wants}")
        if board_for_interface(interface)["ble_filter"]:
            print("arg {number=6}{call=--ble-filter}"
                  "{display=Only these devices}"
                  "{type=string}"
                  "{placeholder=aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66}"
                  # Checked in the dialog, so a mistyped address is caught before
                  # Wireshark commits to a capture rather than after, when the
                  # message has nowhere useful to appear.
                  r"{validation=^\s*$|^\s*([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
                  r"(\s*[, ]\s*([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})*\s*$}"
                  "{tooltip=Restricts scanning to up to eight addresses, filtered "
                  "by the controller so the rest never cross the USB link. One "
                  "advertiser here produced half of everything a survey heard, so "
                  "this is the difference between watching a device and watching "
                  "a room. Leave empty to hear everything}")
        if board_for_interface(interface)["ble_periodic"]:
            print("arg {number=7}{call=--ble-periodic}"
                  "{display=Follow periodic advertising}"
                  "{type=boolflag}{default=false}"
                  "{tooltip=Syncs to periodic advertising trains as they are "
                  "seen, which is how LE Audio and Auracast broadcasts become "
                  "visible. Off by default because syncing spends receive "
                  "windows that would otherwise go to advertisements}")
        print("arg {number=5}{call=--ble-phys}{display=Advertising PHYs}"
              "{type=selector}{default=1}"
              "{tooltip=Extended scanning reports both legacy and BLE 5 "
              "extended advertisements. Legacy-only cannot see the latter at "
              "all, and is here so the difference can be measured}")
        print("value {arg=5}{value=1}{display=Extended, 1M (recommended)}")
        print("value {arg=5}{value=5}{display=Extended, 1M and Coded (long "
              "range, at the cost of 1M coverage)}")
        print("value {arg=5}{value=0}{display=Legacy only, no BLE 5 "
              "extended advertisements}")
        return

    if not is_wifi(interface):
        return

    # Wi-Fi only. A busy 802.11 channel produces roughly 25x what the USB link
    # carries, so both of these are throughput controls, not preferences.
    print(f"arg {{number=3}}{{call=--snaplen}}{{display=Snapshot length}}"
          f"{{type=integer}}{{range=64,{WIFI_MAX_SNAPLEN}}}"
          f"{{default={WIFI_DEFAULT_SNAPLEN}}}"
          f"{{group=Throughput}}"
          f"{{tooltip=Bytes kept per frame. What is discarded is encrypted "
          f"payload; the headers worth having are at the front}}")
    print("arg {number=4}{call=--filter}{display=Frame types}"
          "{type=selector}{default=5}"
          "{group=Throughput}{tooltip=Control frames are the most numerous and the least "
          "informative, so dropping them buys link budget cheaply}")
    print("value {arg=4}{value=5}{display=Management and data (recommended)}")
    print("value {arg=4}{value=15}{display=Everything, including control}")
    print("value {arg=4}{value=1}{display=Management only (beacons, probes)}")
    print("arg {number=5}{call=--hop}{display=Channel hop}"
          "{type=selector}{default=0}"
          "{group=Sweeping}{tooltip=Sweeps channels during the capture. Each frame carries its "
          "own channel, so a hopped capture stays self-describing. "
          "You will miss whatever lands while the radio is elsewhere}")
    print("value {arg=5}{value=0}{display=Off, stay on one channel}")
    print("value {arg=5}{value=1}{display=1, 6, 11 (non-overlapping)}")
    print("value {arg=5}{value=2}{display=All channels, 1-13}")
    print("arg {number=6}{call=--hop-dwell}{display=Hop dwell (ms)}"
          f"{{type=integer}}{{range={HOP_DWELL_MIN_MS},{HOP_DWELL_MAX_MS}}}"
          f"{{default=500}}"
          "{group=Sweeping}{tooltip=Time on each channel. A beacon interval is about 100 ms, "
          "so below roughly 300 ms you will miss beacons}")
    print("arg {number=7}{call=--bandwidth}{display=Channel width}"
          "{type=selector}{default=0}"
          "{tooltip=Watching a 40 MHz network on its primary channel alone "
          "sees half of it, so this must match the network}")
    print("value {arg=7}{value=0}{display=20 MHz}")
    print("value {arg=7}{value=1}{display=40 MHz, secondary above}")
    print("value {arg=7}{value=2}{display=40 MHz, secondary below}")
    print("arg {number=8}{call=--drop-acks}{display=Drop acknowledgements}"
          "{group=Throughput}"
          "{type=boolflag}{default=false}"
          "{tooltip=Acknowledgements dominate control-frame volume and carry "
          "almost nothing. Only applies when control frames are captured}")
    print("arg {number=9}{call=--csi}{display=CSI sidecar file}"
          "{type=fileselect}{fileext=CSV files (*.csv)}"
          "{tooltip=Writes per-subcarrier channel response beside the capture. "
          "No pcap link type can carry it, so it goes to its own file sharing "
          "the capture timestamps. Costs a few hundred bytes per frame}")


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


#: Key-file labels, and the length each key must be. Zigbee keys are 128-bit;
#: anything else is a typo or a different kind of key, and embedding it would
#: produce a capture that silently fails to decrypt.
KEY_KINDS = {"nwk": ("SECRET_ZIGBEE_NWK", 16), "aps": ("SECRET_ZIGBEE_APS", 16)}


def read_key_file(path: str) -> list[tuple[int, bytes]]:
    """Reads Zigbee keys from a file, for embedding in the capture.

    A path rather than the key itself, because an extcap argument reaches the
    process list and Wireshark's saved configuration. The file holds one key
    per line, blank lines and # comments ignored::

        nwk 0123456789abcdef0123456789abcdef
        aps 00112233445566778899aabbccddeeff

    A bare key with no label is taken as a network key, which is the one
    almost everybody means.

    Raises ValueError naming the offending line. A wrong key produces a
    capture that simply does not decrypt, and hunting that afterwards is far
    worse than refusing it now.
    """
    from esp32c6_sniffer import pcapng

    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError as exc:
        raise ValueError(f"cannot read key file {path}: {exc}") from exc

    keys: list[tuple[int, bytes]] = []
    for number, line in enumerate(lines, 1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        parts = text.split()
        kind = parts[0].lower() if len(parts) > 1 else "nwk"
        digits = (parts[1] if len(parts) > 1 else parts[0]).replace(":", "")
        if kind not in KEY_KINDS:
            raise ValueError(
                f"{path} line {number}: unknown key kind {parts[0]!r}, "
                f"expected one of {', '.join(sorted(KEY_KINDS))}")
        name, want = KEY_KINDS[kind]
        try:
            raw = bytes.fromhex(digits)
        except ValueError:
            raise ValueError(
                f"{path} line {number}: {digits!r} is not hexadecimal") from None
        if len(raw) != want:
            raise ValueError(
                f"{path} line {number}: a {kind} key is {want} bytes "
                f"({want * 2} hex digits), got {len(raw)}")
        keys.append((getattr(pcapng, name), raw))
    if not keys:
        raise ValueError(f"{path} contains no keys")
    return keys


def do_capture(fifo: str, port: str, channel: int, antenna: int,
               control_in: str | None, control_out: str | None,
               interface: str = INTERFACE, snaplen: int | None = None,
               frame_filter: int | None = None, hop: int = 0,
               hop_dwell_ms: int = 500, bandwidth: int = 0,
               drop_acks: bool = False, csi_path: str | None = None,
               ble_interval: int = 0, ble_window: int = 0,
               ble_phys: int | None = None,
               key_file: str | None = None,
               thread_file: str | None = None,
               interface_label: str | None = None,
               ble_filter: str | None = None,
               ble_periodic: bool = False) -> int:
    from esp32c6_sniffer.capture import CaptureSession
    from esp32c6_sniffer.control import (
        Antenna, Bandwidth, CtrlFilter, FrameFilter, Radio,
    )
    from esp32c6_sniffer.csi import CSV_HEADER, to_csv_row

    from esp32c6_sniffer.eapol import HandshakeTracker
    from esp32c6_sniffer.pcapng import PcapngWriter

    radio = {"wifi": Radio.WIFI,
             "ble": Radio.BLE}.get(radio_kind(interface), Radio.IEEE802154)
    # Snapshot length and frame filter apply to Wi-Fi only; sending them on an
    # 802.15.4 capture would be silently ignored, which is worse than not
    # sending them.
    wifi = radio is Radio.WIFI
    session_snaplen = snaplen if wifi else None
    session_filter = (
        FrameFilter(frame_filter) if wifi and frame_filter else None
    )
    hop_channels = hop_sets(interface).get(hop)
    session_bandwidth = Bandwidth(bandwidth) if wifi else None
    session_ctrl = CtrlFilter.NO_ACK if (wifi and drop_acks) else None

    # Read any keys BEFORE the fifo is opened: a bad key file must fail
    # while Wireshark can still show the error, not after it has committed to
    # a capture. A key never appears on the command line -- only a path to it
    # does -- so it stays out of process lists and shell history.
    decryption_keys: list[tuple[int, bytes]] = []
    if key_file:
        try:
            decryption_keys = read_key_file(key_file)
        except ValueError as exc:
            sys.stderr.write(str(exc) + os.linesep)
            return 1

    # Thread credentials, read on the same terms and for the same reason: a
    # bad file must fail while Wireshark can still show why. Unlike the Zigbee
    # keys this cannot go in the capture -- Wireshark defines no 802.15.4
    # secrets type -- so it is installed into the key table instead, which is
    # a side effect the option's tooltip states plainly.
    thread_note: str | None = None
    if thread_file:
        from esp32c6_sniffer.thread import (
            ThreadKeyError, install_key, read_credentials,
        )
        try:
            creds = read_credentials(thread_file)
        except ThreadKeyError as exc:
            sys.stderr.write(str(exc) + os.linesep)
            return 1
        installed = install_key(creds.key)
        thread_note = f"Thread credentials: {creds.summary()}"
        if installed:
            thread_note += f"; installed into {len(installed)} key table(s)"
        else:
            thread_note += "; already installed"
        # A dataset is authoritative about its own network, and the default
        # channel is 11. Leaving a channel-15 network on 11 produces silence.
        if creds.from_dataset and creds.channel is not None:
            if creds.channel != channel:
                thread_note += (
                    f"; moving from channel {channel} to {creds.channel}"
                )
            channel = creds.channel

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
                # And wake the capture loop, which is otherwise blocked
                # waiting for a frame that may never come. The flag alone is
                # only read once a packet has arrived, so on a quiet channel
                # -- 802.15.4 channel 11 gives a couple of frames a minute
                # here -- the plugin never noticed Wireshark had gone, and
                # Wireshark hung waiting for a child that would not exit.
                session.request_stop()
                return
            if cmd == CTRL_CMD_INITIALIZED:
                # Arrives after Wireshark replays every user-changed control.
                # Writing before this is ignored.
                state["initialized"] = True
                log(f"capture started on channel {session._channel}")
                if thread_note:
                    # Said here rather than on stderr, because the channel may
                    # have moved and the user should see which network they
                    # are actually pointed at.
                    log(thread_note)
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
    # Opened before the capture pipe so a bad path fails immediately rather
    # than after Wireshark has already started showing packets.
    csi_file = None
    csi_written = 0
    if csi_path and wifi:
        csi_file = open(csi_path, "w", encoding="utf-8", newline="")
        print(CSV_HEADER, file=csi_file)
        # Flushed now so the file is readable even if the capture is killed
        # rather than stopped, which is how Wireshark often ends one.
        csi_file.flush()

    def on_csi(record) -> None:
        nonlocal csi_written
        print(to_csv_row(record), file=csi_file)
        csi_written += 1
        # Flushed regularly rather than per record: CSI arrives as fast as
        # frames do, and this file is read after the capture, not during.
        if csi_written % 50 == 0:
            csi_file.flush()

    with open(fifo, "wb") as pipe:
        # The link type comes from the interface table, which is the same
        # table --extcap-dlts answers from, so the file header and what
        # Wireshark was told can never disagree.
        #
        # This was a hard-coded "Wi-Fi or else 802.15.4" ternary, and adding a
        # third radio made it silently label BLE records as 802.15.4 TAP: 448
        # frames captured and not one of them dissected.
        session_linktype = INTERFACES[interface]["dlt"]
        # pcapng rather than classic pcap, so the capture describes itself:
        # what took it, on which radio, and -- written at close -- how many
        # frames the board dropped before the host ever saw them. In a pcap
        # all of that lives outside the file and is lost the moment the
        # capture is handed to somebody else.
        spec = INTERFACES[interface]
        writer = PcapngWriter(
            pipe, session_linktype,
            hardware=board_for_interface(interface)["hardware"],
            os_name=f"{platform.system()} {platform.release()}",
            application="esp32c6-sniffer extcap",
            # The name Wireshark used, not the bare radio: with two boards
            # attached that carries the port, so a capture stays attributable
            # to the board that took it, and the per-radio profile still
            # matches because it looks for the radio within the name.
            interface_name=interface_label or interface,
            interface_description=(
                f"{spec['display']} ({spec['band']})"
                + (f", on {port}" if interface_label
                   and PORT_SEPARATOR in interface_label else "")
                + (f", channel {channel}" if spec["min"] is not None else "")),
        )
        for secret_type, secret in decryption_keys:
            # Before any packet: Wireshark applies a secret to frames it has
            # yet to dissect, not retrospectively to ones already on screen.
            writer.write_secret(secret_type, secret)
        writer.flush()
        capture_started = time.time()

        def write_statistics(s, reraise: bool = False) -> None:
            """Puts the board's own counters into the file.

            Without this the answer to "did I miss anything?" lives only in a
            toolbar log that nobody keeps, and a capture read back months
            later cannot be told apart from a quiet channel.

            Sequence gaps count as drops because that is what they are: frames
            the board numbered and the host never received.
            """
            try:
                writer.write_statistics(
                    received=s.fw_frames_captured or s.frames,
                    dropped=(s.fw_isr_queue_full + s.fw_link_rejected
                             + s.fw_frames_dropped_ringfull
                             + s.sequence_gaps),
                    start_time_s=capture_started,
                    end_time_s=time.time())
                writer.flush()
            except Exception:
                # Wireshark closing first makes this a broken pipe. For the
                # heartbeat that IS the signal to stop, so it asks to see it;
                # for the ordinary callers the capture is already written and
                # losing a footer is not worth an error over a stop the user
                # asked for.
                if reraise:
                    raise


        if control_out:
            fp_out = open(control_out, "wb", 0)
        fp_in = open(control_in, "rb", 0) if control_in else None

        # Both radios share one 2.4 GHz front end, and leaving the 802.15.4
        # radio ENABLED when a host disconnects leaves the Wi-Fi receiver deaf
        # until the RF domain is power-gated. The board records that in RTC
        # memory; this reads the flag and power-cycles before capturing.
        #
        # It has to be here, not only in the survey tools. Without it the
        # ordinary path -- capture Zigbee in Wireshark, then switch to Wi-Fi --
        # produced a silently EMPTY capture, with no error anywhere, which is
        # the worst possible way for this to fail.
        # The session power-cycles the radio itself when 802.15.4 has left the
        # shared front end deaf; this only reports it. Held rather than logged
        # at once, because the toolbar accepts nothing until Wireshark says it
        # has initialised, which is after the session opens.
        deferred_log: list[str] = []

        # Wi-Fi only, and only worth the per-frame cost there. A WPA2 capture
        # is decryptable only if the four-way handshake was caught, and the
        # handshake happens when a device joins -- a moment, not a state. Told
        # at the time, you know the capture is worth keeping; told never, you
        # find out when you try to read it and the join is hours in the past.
        handshakes = HandshakeTracker() if radio is Radio.WIFI else None

        # Comma or space separated, because a Wireshark option is one text
        # field and people will type it either way.
        filter_addresses = []
        if ble_filter and radio is Radio.BLE:
            filter_addresses = [a for a in ble_filter.replace(",", " ").split()
                                if a]

        # The packet loop and the heartbeat both write to the pipe, from
        # different threads. Interleaving two pcapng blocks produces a file
        # that is unreadable from the point they collide.
        write_lock = threading.Lock()

        with CaptureSession(port, channel=channel,
                            antenna=Antenna(antenna),
                            radio=radio,
                            snaplen=session_snaplen,
                            frame_filter=session_filter,
                            bandwidth=session_bandwidth,
                            ctrl_filter=session_ctrl,
                            ble_interval_ms=ble_interval,
                            ble_window_ms=ble_window,
                            ble_phys=ble_phys,
                            ble_filter=filter_addresses,
                            ble_periodic=ble_periodic,
                            board=board_for_interface(interface)["id"],
                            baud=board_for_interface(interface)["baud"],
                            csi_sink=on_csi if csi_file else None) as session:
            thread = None
            if fp_in is not None:
                thread = threading.Thread(target=reader, args=(fp_in, session),
                                          daemon=True)
                thread.start()
            else:
                state["initialized"] = True   # no toolbar; nothing to wait for
                if thread_note:
                    log(thread_note)

            if session.recovered_from_802154:
                deferred_log.append(
                    "802.15.4 had been used; power-cycled the radio first")
            for message in deferred_log:
                log(message)

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

            # A heartbeat, because everything else in this loop is driven by
            # packets arriving. On a quiet channel none do: 802.15.4 channel
            # 11 gives a couple of frames a minute here, and the plugin
            # therefore never wrote to the pipe, never learned that Wireshark
            # had closed it, and never exited -- so Wireshark hung on shutdown
            # waiting for a child that was waiting for a frame.
            #
            # Writing the statistics block once a second doubles as the test:
            # a write to a closed pipe raises, which is the only reliable
            # signal that the host has gone. It also means a quiet capture
            # gets its drop counters at all, which it previously did not.
            def heartbeat() -> None:
                while state["running"]:
                    time.sleep(1.0)
                    if not state["running"]:
                        return
                    try:
                        with write_lock:
                            write_statistics(session.stats, reraise=True)
                    except Exception:
                        state["running"] = False
                        session.request_stop()
                        return

            threading.Thread(target=heartbeat, daemon=True).start()

            next_report = time.monotonic() + 1.0
            try:
                for record, timestamp, original_len in session.records():
                    note = None
                    if handshakes is not None:
                        # The 802.11 frame sits after the radiotap header,
                        # whose length is its third and fourth bytes.
                        radiotap_len = int.from_bytes(record[2:4], "little")
                        key_frame, done = handshakes.feed(record[radiotap_len:])
                        if key_frame is not None:
                            # Annotated in the FILE, not only in the log. The
                            # log is gone when Wireshark closes; a comment is
                            # part of the capture and filterable with
                            # pkt_comment months later.
                            note = (f"WPA four-way handshake, message "
                                    f"{key_frame.message} of 4 "
                                    f"({key_frame.bssid})")
                        if done is not None:
                            log(f"four-way handshake captured for "
                                f"{done.bssid} <- {done.station}: with the "
                                f"passphrase, this session can be decrypted")
                            control_write(
                                fp_out, CTRL_ARG_NONE, CTRL_CMD_INFORMATION,
                                (f"WPA handshake captured for {done.bssid}. "
                                 f"Add the passphrase under Edit, Preferences, "
                                 f"Protocols, IEEE 802.11 to decrypt this "
                                 f"capture. Filter: pkt_comment").encode())
                    with write_lock:
                        writer.write_packet(record, timestamp,
                                            original_length=original_len,
                                            comment=note)
                        # Flush per packet or Wireshark shows nothing until
                        # the buffer fills, which looks like a broken capture.
                        writer.flush()
                    if not state["running"]:
                        break
                    now = time.monotonic()
                    if now >= next_report:
                        next_report = now + 1.0
                        s = session.stats
                        # An interface-statistics block every second, not only
                        # at close. Wireshark stops a capture by closing the
                        # pipe, so anything written in a cleanup path is
                        # written into a pipe nobody is reading and never
                        # reaches the file. dumpcap writes these periodically
                        # for the same reason. A reader takes the last one.
                        write_statistics(s)
                        extra = ""
                        if s.fw_recoveries:
                            # A workaround for a fault that is not ours, so it
                            # is surfaced rather than hidden.
                            extra += (f", receiver rebuilt {s.fw_recoveries}x "
                                      f"after going deaf")
                        if csi_file is not None:
                            extra += (f", CSI {csi_written} records"
                                      f"{f', {s.fw_csi_dropped} dropped'
                                         if s.fw_csi_dropped else ''}")
                        if s.fw_stalled_seconds:
                            extra += (f", no frames for {s.fw_stalled_seconds}s"
                                      f" -- if this persists the receiver has "
                                      f"latched deaf; stop the capture and run "
                                      f"tools/wifi_survey.py --recover")
                        if s.fw_frames_truncated:
                            # Not loss: the snapshot length is deliberate, and
                            # what it cuts is encrypted payload.
                            extra += (f", {s.fw_frames_truncated} truncated")
                        if radio is Radio.BLE and s.fw_ble_periodic_seen:
                            extra += (f", periodic {s.fw_ble_periodic_seen} "
                                      f"seen/{s.fw_ble_periodic_synced} "
                                      f"synced/{s.fw_ble_periodic_reports} "
                                      f"reports")
                        if s.fw_ble_periodic_refused:
                            # The controller was asked for a sync and said no.
                            # It holds one at a time, so this is the board
                            # spending create-sync commands on something that
                            # cannot succeed -- worth seeing, and invisible
                            # until the BLE counters were read at all.
                            extra += (f", {s.fw_ble_periodic_refused} periodic "
                                      f"syncs refused")
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
                # The board's own counters, written into the file. Without
                # this the answer to "did I miss anything?" lives only in a
                # toolbar log that nobody keeps, so a capture read back later
                # cannot be told apart from a quiet channel.
                # A last one, for the case where the capture ends on our side
                # -- a board unplugged, a --count limit -- and the pipe is
                # still open. When Wireshark stops us the pipe is already
                # closed and this writes nowhere, which is why the periodic
                # block above exists.
                write_statistics(session.stats)
                if csi_file is not None:
                    csi_file.close()
                if fp_out is not None:
                    fp_out.close()
    return 0


def capture_failure_message(port: str, exc: Exception,
                            found: list[str]) -> str:
    """What Wireshark shows the user when a capture cannot start.

    Names the port that failed and, if a board is somewhere else, where. A
    board found on the very port that failed is a different fault -- it is
    there and did not answer -- and pointing the user at the port they had
    already chosen, as this once did, reads as the fix while being no help.
    The nRF54L15 produced exactly that when stale data in its USB bridge ate
    the reply to the first command of a session.
    """
    lines = [f"cannot capture on {port}: {exc}"]
    if port.casefold() in {f.casefold() for f in found}:
        lines.append(
            f"{port} is where the board is, so the port is right: the board "
            f"did not answer. Start the capture again; if it still does not "
            f"answer, unplug the board and plug it back in.")
    elif found:
        lines.append("the board looks like it is on: " + ", ".join(found))
    else:
        # Named from the board table, so a board added there is named here
        # too. This said "no ESP32-C6 found" to nRF54L15 owners, which reads
        # as the plugin not supporting their board at all.
        names = [board["display"] for board in BOARDS.values()]
        either = (names[0] if len(names) == 1
                  else ", ".join(names[:-1]) + " or " + names[-1])
        lines.append(
            f"no {either} found on any serial port. Check the cable is "
            f"data-capable: a charge-only one enumerates nothing and looks "
            f"exactly like a dead board.")
    return os.linesep.join(lines) + os.linesep


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
    # Resolved lazily rather than here, so listing interfaces does not pay for
    # a serial enumeration it has no use for.
    parser.add_argument("--port", default=None)
    # No default here: it depends on which interface was named, and a fixed
    # 802.15.4 default would be an invalid Wi-Fi channel.
    parser.add_argument("--channel", type=int, default=None)
    parser.add_argument("--antenna", type=int, default=0)
    parser.add_argument("--snaplen", type=int, default=None)
    parser.add_argument("--filter", dest="frame_filter", type=int, default=None)
    parser.add_argument("--hop", type=int, default=0)
    parser.add_argument("--hop-dwell", dest="hop_dwell", type=int, default=500)
    parser.add_argument("--bandwidth", type=int, default=0)
    parser.add_argument("--drop-acks", dest="drop_acks", action="store_true")
    parser.add_argument("--csi", dest="csi_path", default=None)
    parser.add_argument("--keys", dest="key_file", default=None)
    parser.add_argument("--thread", dest="thread_file", default=None)
    parser.add_argument("--ble-interval", dest="ble_interval", type=int,
                        default=0)
    parser.add_argument("--ble-window", dest="ble_window", type=int, default=0)
    parser.add_argument("--ble-phys", dest="ble_phys", type=int, default=None)
    parser.add_argument("--ble-filter", dest="ble_filter", default=None)
    parser.add_argument("--ble-periodic", dest="ble_periodic",
                        action="store_true")
    args, unknown = parser.parse_known_args(argv)

    # Wireshark shows a capture-filter box for extcap interfaces and passes
    # whatever is typed there. parse_known_args swallowed it, so a filter was
    # accepted and then silently ignored -- the capture ran unfiltered and
    # looked fine, which is the worst way to handle an instruction.
    if "--extcap-capture-filter" in unknown:
        sys.stderr.write(
            "a capture filter cannot be applied here: filtering happens on "
            "the board, before the USB link, and it does not speak BPF. Use "
            "the interface options instead -- Frame types and Channel for "
            "Wi-Fi, Channel for 802.15.4 -- or filter after capture with a "
            "display filter." + os.linesep)
        return 1
    if args.port is None:
        args.port = default_port()

    if args.extcap_interfaces:
        print_interfaces(args.extcap_interface)
        return 0

    # An interface may name its board -- "esp32c6-wifi@COM7" -- when more than
    # one is attached. The port it names wins over the default, so selecting
    # the second board's Wi-Fi interface captures on the second board rather
    # than on whichever one was found first.
    interface_name = args.extcap_interface
    interface_port = None
    if interface_name is not None:
        interface_name, interface_port = split_interface(interface_name)
        if interface_name not in INTERFACES:
            sys.stderr.write(f"unknown interface: {args.extcap_interface}"
                             + os.linesep)
            return 1
        if interface_port:
            args.port = interface_port

    # Every remaining mode is interface-specific. Defaulting to 802.15.4
    # keeps a bare invocation working, as it did before Wi-Fi existed.
    interface = interface_name or INTERFACE
    spec = INTERFACES[interface]

    if args.extcap_dlts:
        print_dlts(interface)
        return 0
    if args.extcap_config:
        print_config(interface, args.extcap_reload_option, args.port)
        return 0
    if args.capture:
        if not args.fifo:
            sys.stderr.write("--capture requires --fifo\n")
            return 1
        channel = args.channel if args.channel is not None else spec["default"]
        # BLE has no channel: the controller rotates the three advertising
        # channels itself. Asking for one is refused rather than ignored --
        # silently accepting an option that cannot be honoured is how a user
        # ends up believing a capture is something it is not.
        if spec["min"] is None:
            if args.channel is not None:
                sys.stderr.write(
                    f"{spec['display']} has no selectable channel"
                    + os.linesep)
                return 1
        elif not spec["min"] <= channel <= spec["max"]:
            sys.stderr.write(
                f"channel {channel} outside {spec['min']}-{spec['max']}\n"
            )
            return 1
        if args.snaplen is not None and not 1 <= args.snaplen <= WIFI_MAX_SNAPLEN:
            sys.stderr.write(
                f"snaplen {args.snaplen} outside 1-{WIFI_MAX_SNAPLEN}" + os.linesep
            )
            return 1
        # 2 is the 2M PHY bit, which primary advertising never uses; the
        # controller rejects a bitmap containing it and the whole scan setup
        # fails, so it is refused here where the reason can be given.
        if args.ble_phys is not None and args.ble_phys not in (0, 1, 4, 5):
            sys.stderr.write(
                f"BLE PHY selection {args.ble_phys} is not one of 0 (legacy), "
                f"1 (1M), 4 (Coded) or 5 (both)" + os.linesep)
            return 1
        # Validated against THIS radio's sets. BLE has none -- the
        # controller rotates the advertising channels itself -- so asking for
        # one there is refused rather than silently ignored.
        if args.hop not in hop_sets(interface):
            sys.stderr.write(
                f"hop set {args.hop} is not offered for {interface}"
                + os.linesep)
            return 1
        # A dwell outside this range is not merely odd: a negative one reaches
        # time.sleep() on the hop thread, which raises there and kills hopping
        # silently while the capture carries on looking healthy.
        if not HOP_DWELL_MIN_MS <= args.hop_dwell <= HOP_DWELL_MAX_MS:
            sys.stderr.write(
                f"hop dwell {args.hop_dwell} outside "
                f"{HOP_DWELL_MIN_MS}-{HOP_DWELL_MAX_MS} ms" + os.linesep)
            return 1
        try:
            return do_capture(args.fifo, args.port, channel, args.antenna,
                              args.extcap_control_in, args.extcap_control_out,
                              interface, args.snaplen, args.frame_filter,
                              args.hop, args.hop_dwell, args.bandwidth,
                              args.drop_acks, args.csi_path,
                              args.ble_interval, args.ble_window,
                              args.ble_phys, args.key_file,
                              args.thread_file,
                              interface_label=args.extcap_interface,
                              ble_filter=args.ble_filter,
                      ble_periodic=args.ble_periodic)
        except (OSError, RuntimeError) as exc:
            # Usually the wrong serial port, which used to reach the user as a
            # Python traceback in a Wireshark dialog.
            #
            # RuntimeError as well as OSError: the capture library wraps the
            # serial failure after exhausting its retries, so catching only
            # OSError here caught nothing and the traceback still escaped.
            # TimeoutError, a board that did not answer, is an OSError.
            sys.stderr.write(capture_failure_message(
                args.port, exc, [port for port, _board in find_board_ports()]))
            return 1

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
