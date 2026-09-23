"""The boards this project drives, and a raw command link to one.

The table was the extcap script's, where nothing else could reach it, so every
tool that opened a port did so the ESP32-C6's way: 115200 baud and no
handshake. The C6 does not mind -- its port is USB CDC, with no line rate --
but the nRF54L15 sits behind a UART bridge at 1 Mbaud whose leftovers can eat
the first reply. survey.py and spectrum.py could not drive it at all.

Nothing here imports pyserial at module level: the extcap must be able to list
its interfaces with the package importable and nothing else.
"""

from __future__ import annotations

import time

from .control import Command, decode_reply, encode_command
from .framing import FrameType
from .parser import StreamParser

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
        # Resets when its port opens, so nothing is left over to hand across.
        "bridged": False,
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
        # The SAMD11 keeps whole USB packets that were in flight when the
        # previous session closed, and releases them in front of the next
        # thing the board sends -- on opening, the reply to GET_INFO.
        "bridged": True,
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


#: How long a bridged board's first GET_INFO is waited for. A reply normally
#: arrives in milliseconds; this only decides how soon one that stale data has
#: eaten is given up on and asked for again.
BRIDGE_FIRST_REPLY_S = 0.5


def board_by_id(board_id: str) -> dict:
    """The BOARDS entry with this id. KeyError for one that does not exist."""
    for board in BOARDS.values():
        if board["id"] == board_id:
            return board
    raise KeyError(board_id)


def bridged_board_ids() -> frozenset[str]:
    return frozenset(b["id"] for b in BOARDS.values() if b["bridged"])


def board_on_port(device: str, comports=None) -> dict | None:
    """The board on a serial port, by the USB id it enumerates as.

    None for a port that is not one of ours, or when ports cannot be listed:
    an unrecognised id is not guessed at, because a guessed board has the
    wrong capabilities. comports is for tests; it defaults to pyserial's list.
    """
    if comports is None:
        try:
            from serial.tools import list_ports
            comports = list_ports.comports()
        except Exception:
            return None
    for port in comports:
        if port.device == device:
            return BOARDS.get((port.vid, port.pid))
    return None


class BoardLink:
    """Raw command access to one board, for tools a CaptureSession cannot serve.

    Opens at the rate the board on the port needs, and asks for GET_INFO once
    open: again, after clearing, when a bridged board's first reply is lost to
    stale data. A port whose board cannot be identified is opened as a C6 was
    before this class existed, which is what every tool did then.

    ser and parser stay public: the tools read captured frames through them
    between commands.
    """

    def __init__(self, port: str, board: dict | None = None, comports=None,
                 serial_factory=None, timeout: float = 5.0) -> None:
        self.port = port
        self.board = (board or board_on_port(port, comports)
                      or BOARDS[(ESP32C6_USB_VID, ESP32C6_USB_PID)])
        self.timeout = timeout
        self.firmware_version: int | None = None
        self.ser = None
        self.parser = StreamParser()
        self._serial_factory = serial_factory

    def open(self) -> "BoardLink":
        factory = self._serial_factory
        if factory is None:
            import serial
            factory = serial.Serial
        self.ser = factory(self.port, self.board["baud"], timeout=0.05)
        try:
            try:
                self.ser.set_buffer_size(rx_size=1 << 20)
            except (AttributeError, OSError):
                pass
            self.ser.reset_input_buffer()
            self.parser = StreamParser()
            self.firmware_version = self._hello()["value"]
        except BaseException:
            self.close()
            raise
        return self

    def _hello(self) -> dict:
        if not self.board["bridged"]:
            return self.command(Command.GET_INFO)
        try:
            return self.command(Command.GET_INFO, timeout=BRIDGE_FIRST_REPLY_S)
        except TimeoutError:
            pass
        self.ser.reset_input_buffer()
        self.parser = StreamParser()
        return self.command(Command.GET_INFO)

    def command(self, command: Command, value: int = 0, radio=None,
                timeout: float | None = None) -> dict:
        """Sends one command and returns its reply. Frames arriving meanwhile
        are dropped: a tool that wants them reads through ser and parser."""
        kwargs = {} if radio is None else {"radio": radio}
        self.ser.write(encode_command(command, value, **kwargs))
        self.ser.flush()
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while time.monotonic() < deadline:
            for frame in self.parser.feed(self.ser.read(4096)):
                if frame.ftype is FrameType.CONTROL_REPLY:
                    reply = decode_reply(frame.payload)
                    if reply["command"] is command:
                        return reply
        raise TimeoutError(f"no reply to {command.name} from the "
                           f"{self.board['display']} on {self.port}")

    def close(self) -> None:
        if self.ser is not None:
            self.ser.close()
            self.ser = None

    def __enter__(self) -> "BoardLink":
        return self.open()

    def __exit__(self, *exc) -> None:
        self.close()
