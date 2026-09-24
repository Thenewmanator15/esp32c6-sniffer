"""The 802.15.4 MAC header, read far enough to say whose frame it is.

The channel survey counts frames; this is what lets it name the networks behind
them. Everything read here is in the clear even on a network whose payloads are
encrypted: frame type, PAN ID, addresses, the security flag, a command's
identifier, and the first byte after the header -- which is enough to tell
Zigbee from Thread:

* **MAC security** is Thread's. Zigbee encrypts above the MAC layer and sends
  its frames with the MAC security flag clear.
* An unsecured data frame whose payload opens with a **6LoWPAN** dispatch is
  Thread (MLE travels that way). One opening with a **Zigbee NWK** frame
  control, protocol version 2, is Zigbee.
* A **beacon** names its stack in its payload's first byte: 0x00 for Zigbee,
  0x03 for Thread.

Nothing decides when none of these applies: acknowledgements, most commands,
and frames of any other stack stay unclassified rather than guessed.
"""

from __future__ import annotations

from dataclasses import dataclass

FRAME_BEACON = 0
FRAME_DATA = 1
FRAME_ACK = 2
FRAME_COMMAND = 3

ADDR_NONE = 0
ADDR_SHORT = 2
ADDR_EXT = 3

COMMAND_DATA_REQUEST = 0x04

#: Bytes the key identifier adds to the auxiliary security header, by mode.
_KEY_ID_LEN = {0: 0, 1: 1, 2: 5, 3: 9}

BEACON_PROTOCOL_ZIGBEE = 0x00
BEACON_PROTOCOL_THREAD = 0x03


@dataclass(frozen=True)
class MacHeader:
    frame_type: int
    version: int
    secured: bool
    dst_pan: int | None
    src_pan: int | None
    dst_addr: int | None
    src_addr: int | None
    src_is_ext: bool
    command_id: int | None
    network: str | None

    @property
    def pan(self) -> int | None:
        """The PAN the frame belongs to: its source PAN, else its destination's."""
        return self.src_pan if self.src_pan is not None else self.dst_pan

    @property
    def is_data_request(self) -> bool:
        """A device polling its parent for data: what a sleepy device does."""
        return self.frame_type == FRAME_COMMAND and self.command_id == COMMAND_DATA_REQUEST


def _pans_present(version: int, compressed: bool, dst_mode: int, src_mode: int) -> tuple[bool, bool]:
    """Whether the destination and source PAN IDs are in the frame.

    Before 802.15.4-2015 the rule is simple: each address brings its PAN, and
    compression drops the source's. The 2015 revision replaced it with a table
    (7.2.2.6), which this follows.
    """
    dst, src = dst_mode != ADDR_NONE, src_mode != ADDR_NONE
    if version < 2:
        return dst, src and not (compressed and dst)
    if not dst and not src:
        return compressed, False
    if dst and not src:
        return not compressed, False
    if src and not dst:
        return False, not compressed
    if dst_mode == ADDR_EXT and src_mode == ADDR_EXT:
        return not compressed, False
    return True, not compressed


def _network(frame_type: int, secured: bool, payload: bytes) -> str | None:
    if secured:
        return "Thread"
    if not payload:
        return None
    first = payload[0]
    if frame_type == FRAME_BEACON:
        return {BEACON_PROTOCOL_ZIGBEE: "Zigbee", BEACON_PROTOCOL_THREAD: "Thread"}.get(first)
    if frame_type != FRAME_DATA:
        return None
    # 6LoWPAN dispatches: uncompressed IPv6 0x41, IPHC 0x60-0x7F, mesh
    # 0x80-0xBF, fragments 0xC0-0xE7.
    if first == 0x41 or 0x60 <= first <= 0xE7:
        return "Thread"
    # Zigbee NWK frame control: frame type data or command, protocol version 2.
    if first & 0x3C == 0x08 and first & 0x03 in (0, 1):
        return "Zigbee"
    return None


def _beacon_payload(body: bytes) -> bytes | None:
    """The beacon payload, past the superframe, GTS and pending address fields."""
    pos = 2
    if len(body) < pos + 1:
        return None
    gts_count = body[pos] & 0x07
    pos += 1
    if gts_count:
        pos += 1 + 3 * gts_count
    if len(body) < pos + 1:
        return None
    pending = body[pos]
    pos += 1 + 2 * (pending & 0x07) + 8 * ((pending >> 4) & 0x07)
    if len(body) < pos:
        return None
    return body[pos:]


def parse(psdu: bytes) -> MacHeader | None:
    """Reads the MAC header of one frame, or None if it is too short or invalid.

    The frame check sequence, if present, is simply ignored: nothing here reads
    as far as the end of the frame.
    """
    if len(psdu) < 3:
        return None
    fcf = int.from_bytes(psdu[:2], "little")
    frame_type = fcf & 0x07
    secured = bool(fcf & 0x08)
    compressed = bool(fcf & 0x40)
    seq_suppressed = bool(fcf & 0x100)
    ie_present = bool(fcf & 0x200)
    dst_mode = (fcf >> 10) & 0x03
    version = (fcf >> 12) & 0x03
    src_mode = (fcf >> 14) & 0x03
    if dst_mode == 1 or src_mode == 1 or frame_type > FRAME_COMMAND:
        return None

    pos = 2 if (version == 2 and seq_suppressed) else 3
    dst_pan_present, src_pan_present = _pans_present(version, compressed, dst_mode, src_mode)

    def take(n: int) -> int | None:
        nonlocal pos
        if len(psdu) < pos + n:
            return None
        value = int.from_bytes(psdu[pos:pos + n], "little")
        pos += n
        return value

    def address(mode: int) -> tuple[bool, int | None]:
        if mode == ADDR_NONE:
            return True, None
        value = take(2 if mode == ADDR_SHORT else 8)
        return value is not None, value

    dst_pan = src_pan = None
    if dst_pan_present:
        dst_pan = take(2)
        if dst_pan is None:
            return None
    ok, dst_addr = address(dst_mode)
    if not ok:
        return None
    if src_pan_present:
        src_pan = take(2)
        if src_pan is None:
            return None
    elif compressed and version < 2 and dst_pan is not None and src_mode != ADDR_NONE:
        src_pan = dst_pan
    ok, src_addr = address(src_mode)
    if not ok:
        return None

    if secured:
        if len(psdu) < pos + 1:
            return None
        control = psdu[pos]
        counter_suppressed = version == 2 and bool(control & 0x20)
        aux_len = 1 + (0 if counter_suppressed else 4) + _KEY_ID_LEN[(control >> 3) & 0x03]
        if len(psdu) < pos + aux_len:
            return None
        pos += aux_len

    payload = psdu[pos:]
    command_id = None
    network = None
    if ie_present:
        # Header IEs would have to be walked to find the payload; the addresses
        # are all the survey needs from such a frame.
        payload = b""
    if frame_type == FRAME_COMMAND and payload:
        command_id = payload[0]
    if frame_type == FRAME_BEACON and not secured:
        network = _network(frame_type, False, _beacon_payload(payload) or b"")
    else:
        network = _network(frame_type, secured, payload)

    return MacHeader(frame_type=frame_type, version=version, secured=secured,
                     dst_pan=dst_pan, src_pan=src_pan,
                     dst_addr=dst_addr, src_addr=src_addr,
                     src_is_ext=src_mode == ADDR_EXT,
                     command_id=command_id, network=network)
