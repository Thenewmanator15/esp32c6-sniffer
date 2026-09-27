"""Making the Wi-Fi receiver usable again after the 802.15.4 radio has run.

Both radios share one 2.4 GHz front end. Leave the 802.15.4 radio running when
the host goes -- a capture killed rather than stopped -- and the Wi-Fi receiver
is deaf afterwards: 8 times in 8 on this board, measured 2026-09-27. The
firmware records that in RTC memory, where it survives the reset opening the
port causes, and answers RADIO_DIRTY.

What cures it is starting the 802.15.4 radio and stopping it cleanly -- put to
sleep, then disabled -- which hands the front end back: every episode it has
been tried on, at once, with no time spent receiving. The deep-sleep power-gate
this module used to do usually cures it too, but left two episodes deaf
through 16 attempts between them, one of them for an hour. So the hand-back
goes first, and the power-gate stays as the fallback.

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
         value: int = 0, wait: float = 3.0, radio: Radio = Radio.WIFI):
    ser.write(encode_command(command, value, radio=radio))
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
    """Hands the front end back if 802.15.4 was left running.

    Returns True if it did. Opens and closes the port itself, so call it
    before opening a capture session rather than during one.

    A board too old to answer RADIO_DIRTY is left alone: an unnecessary
    hand-back costs nothing much, but the firmware version check will report
    the mismatch anyway.
    """
    ser = _open(port)
    try:
        time.sleep(settle)
        parser = StreamParser()
        reply = _ask(ser, parser, Command.RADIO_DIRTY)
        if reply is None or not reply["ok"] or not reply["value"]:
            return False
        _hand_back_on(ser, parser)
    finally:
        ser.close()
    return True


def hand_back(port: str, settle: float = 2.0) -> None:
    """Starts the 802.15.4 radio and stops it cleanly, whatever the flag says.

    For a receiver found deaf with the flag clear, and for --recover. Opens and
    closes the port itself, like ensure_wifi_ready.
    """
    ser = _open(port)
    try:
        time.sleep(settle)
        _hand_back_on(ser, StreamParser())
    finally:
        ser.close()


def _hand_back_on(ser: serial.Serial, parser: StreamParser) -> None:
    # SET_CHANNEL is what starts the radio on the C6. The channel is any
    # valid one; nothing is captured.
    ieee = Radio.IEEE802154
    _ask(ser, parser, Command.SET_RADIO, int(ieee), radio=ieee)
    _ask(ser, parser, Command.SET_CHANNEL, 11, radio=ieee)
    _ask(ser, parser, Command.STOP, radio=ieee)


def power_cycle(port: str) -> None:
    """Power-gates the radio domain and waits for the board to come back.

    The fallback, for a receiver the hand-back did not cure. It usually cures
    the deafness 802.15.4 left running causes, but not always, and it cured
    one that had some other cause. Opens and closes the port itself, like
    ensure_wifi_ready.
    """
    ser = _open(port)
    try:
        _power_cycle_on(ser, StreamParser())
    finally:
        ser.close()
    _await_return(port)


def _power_cycle_on(ser: serial.Serial, parser: StreamParser) -> None:
    _ask(ser, parser, Command.RADIO_POWER_CYCLE)
    time.sleep(2.0)


def _await_return(port: str) -> None:
    time.sleep(POWER_CYCLE_SETTLE_S)
    # Prove it came back rather than assuming, so a caller can rely on the
    # port existing.
    _open(port).close()
