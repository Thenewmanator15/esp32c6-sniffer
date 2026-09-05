"""Making the Wi-Fi receiver usable again after the 802.15.4 radio has run.

Both radios share one 2.4 GHz front end, and enabling the 802.15.4 one leaves
the Wi-Fi receiver deaf until the RF domain is power-gated. Measured on this
board: 633 Wi-Fi frames captured immediately after a power cycle, 0 after a
30-second 802.15.4 capture, while idling the same 30 seconds cost nothing at
all. `esp_ieee802154_disable()` is the documented teardown and does not hand
the front end back; putting the radio to sleep first makes no difference.

Nothing short of power-gating recovers it -- not a Wi-Fi driver rebuild, not a
reflash, not a full erase-flash -- so the firmware records whether 802.15.4 has
run since boot and the host power-cycles before a Wi-Fi capture when it has.

Without this a Wi-Fi capture started after an 802.15.4 one returns nothing,
silently and indistinguishably from an empty channel.
"""

from __future__ import annotations

import time

import serial

from .control import Command, Radio, decode_reply, encode_command
from .framing import FrameType
from .parser import StreamParser

#: How long the board takes to deep-sleep, reset and re-enumerate over USB.
POWER_CYCLE_SETTLE_S = 6.0


def _open(port: str, timeout: float = 30.0) -> serial.Serial:
    """Opens the port, waiting out a USB re-enumeration."""
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            ser = serial.Serial(port, 115200, timeout=0.05)
            try:
                ser.set_buffer_size(rx_size=1 << 20)
            except (AttributeError, OSError):
                pass
            ser.reset_input_buffer()
            return ser
        except (OSError, serial.SerialException) as exc:
            last = exc
            time.sleep(0.5)
    raise RuntimeError(f"cannot open {port}: {last}")


def _ask(ser: serial.Serial, parser: StreamParser, command: Command,
         value: int = 0, wait: float = 3.0):
    ser.write(encode_command(command, value, radio=Radio.WIFI))
    ser.flush()
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        for frame in parser.feed(ser.read(4096)):
            if frame.ftype is FrameType.CONTROL_REPLY:
                reply = decode_reply(frame.payload)
                if reply["command"] is command:
                    return reply
    return None


def ensure_wifi_ready(port: str, settle: float = 2.0) -> bool:
    """Power-cycles the board if 802.15.4 has poisoned the front end.

    Returns True if a power cycle was performed. Opens and closes the port
    itself, so call it before opening a capture session rather than during one.

    A board too old to answer RADIO_DIRTY is left alone: an unnecessary reset
    is worse than a missing optimisation, and the firmware version check will
    report the mismatch anyway.
    """
    ser = _open(port)
    try:
        time.sleep(settle)
        parser = StreamParser()
        reply = _ask(ser, parser, Command.RADIO_DIRTY)
        if reply is None or not reply["ok"] or not reply["value"]:
            return False
        _ask(ser, parser, Command.RADIO_POWER_CYCLE)
        time.sleep(2.0)
    finally:
        ser.close()

    time.sleep(POWER_CYCLE_SETTLE_S)
    # Prove it came back rather than assuming, so a caller that gets True can
    # rely on the port existing.
    _open(port).close()
    return True
