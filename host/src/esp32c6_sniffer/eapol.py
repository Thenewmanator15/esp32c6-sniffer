"""Spotting the WPA/WPA2 four-way handshake as it goes past.

A Wi-Fi capture is encrypted and stays encrypted, with one exception: if you
hold the passphrase AND you captured the four-way handshake, Wireshark can
derive the session keys and decrypt the traffic. The handshake happens only
when a device joins, so it is a moment rather than a state -- miss it and you
wait for the next device to associate, which on a settled network can be hours.

Nothing here decrypts anything or attacks anything. It reads the four frames
that are sent in the clear anyway, notices when a complete set has been seen,
and says so, so that a capture worth keeping is not thrown away unknowingly.

The messages are told apart by the Key Information bits, per IEEE 802.11:

    bit 3  key type, 1 = pairwise
    bit 6  install
    bit 7  key ack
    bit 8  key MIC
    bit 9  secure

    M1  ack, no MIC              access point sends its nonce
    M2  MIC, not secure          client answers with its own
    M3  ack and MIC, secure      access point confirms, install set
    M4  MIC, secure, no key data client acknowledges

Only pairwise messages count. The group-key handshake that follows uses the
same frame type and would otherwise be miscounted as a second four-way.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

#: LLC/SNAP header that precedes an EAPOL frame in 802.11, then the ethertype.
_SNAP = b"\xaa\xaa\x03\x00\x00\x00"
ETHERTYPE_EAPOL = 0x888E

#: EAPOL packet types. 3 is EAPOL-Key, the only one a handshake uses.
EAPOL_TYPE_KEY = 3

#: Key descriptor types: 2 is RSN (WPA2 and WPA3), 254 the older WPA.
KEY_DESCRIPTOR_RSN = 2
KEY_DESCRIPTOR_WPA = 254

KEY_INFO_PAIRWISE = 1 << 3
KEY_INFO_INSTALL = 1 << 6
KEY_INFO_ACK = 1 << 7
KEY_INFO_MIC = 1 << 8
KEY_INFO_SECURE = 1 << 9

FC_TYPE_DATA = 2
FC_SUBTYPE_QOS = 0x08


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


@dataclass(frozen=True)
class EapolKeyFrame:
    message: int          # 1 to 4
    bssid: str
    station: str
    from_ap: bool


def parse_eapol_key(frame: bytes) -> EapolKeyFrame | None:
    """Returns the handshake message in an 802.11 frame, or None.

    Rejects cheaply and early: this runs on every frame of a capture that can
    carry a thousand a second, and all but a handful are not EAPOL at all.
    """
    if len(frame) < 34:
        return None
    fc0, fc1 = frame[0], frame[1]
    if (fc0 >> 2) & 0x03 != FC_TYPE_DATA:
        return None
    subtype = (fc0 >> 4) & 0x0F
    if subtype & 0x04:
        return None                    # null data: no payload to carry EAPOL

    to_ds = bool(fc1 & 0x01)
    from_ds = bool(fc1 & 0x02)
    if to_ds and from_ds:
        return None                    # a mesh frame; four addresses, not ours

    header = 24 + (2 if subtype & FC_SUBTYPE_QOS else 0)
    if len(frame) < header + len(_SNAP) + 2:
        return None
    if frame[header:header + len(_SNAP)] != _SNAP:
        return None
    ethertype = struct.unpack_from(">H", frame, header + len(_SNAP))[0]
    if ethertype != ETHERTYPE_EAPOL:
        return None

    body = header + len(_SNAP) + 2
    if len(frame) < body + 4:
        return None
    if frame[body + 1] != EAPOL_TYPE_KEY:
        return None

    key = body + 4
    if len(frame) < key + 95:
        return None                    # truncated by the snapshot length
    if frame[key] not in (KEY_DESCRIPTOR_RSN, KEY_DESCRIPTOR_WPA):
        return None
    info = struct.unpack_from(">H", frame, key + 1)[0]
    if not info & KEY_INFO_PAIRWISE:
        return None                    # the group handshake, not this one

    data_length = struct.unpack_from(">H", frame, key + 93)[0]

    ack = bool(info & KEY_INFO_ACK)
    mic = bool(info & KEY_INFO_MIC)
    secure = bool(info & KEY_INFO_SECURE)
    if ack and not mic:
        message = 1
    elif mic and not ack and not secure:
        message = 2
    elif ack and mic:
        message = 3
    elif mic and secure and data_length == 0:
        message = 4
    else:
        return None

    address1 = _mac(frame[4:10])
    address2 = _mac(frame[10:16])
    # Addressing depends on direction: from the access point, address 2 is the
    # BSSID; towards it, address 1 is. Getting this backwards pairs each
    # message with the wrong conversation and no handshake ever completes.
    if from_ds:
        return EapolKeyFrame(message, bssid=address2, station=address1,
                             from_ap=True)
    return EapolKeyFrame(message, bssid=address1, station=address2,
                         from_ap=False)


@dataclass
class Handshake:
    bssid: str
    station: str
    messages: set[int] = field(default_factory=set)

    @property
    def complete(self) -> bool:
        """All four seen.

        Wireshark can often manage with fewer, but claiming a capture is
        decryptable and being wrong wastes more of somebody's time than saying
        nothing would.
        """
        return self.messages >= {1, 2, 3, 4}


class HandshakeTracker:
    """Accumulates handshake messages per conversation.

    Keyed on (access point, station): several devices can join at once, and
    interleaved messages from two of them would otherwise look like one
    complete handshake belonging to neither.
    """

    def __init__(self) -> None:
        self.handshakes: dict[tuple[str, str], Handshake] = {}
        self._reported: set[tuple[str, str]] = set()

    def feed(self, frame: bytes):
        """Returns (this frame's message, the handshake it just completed).

        Both, because they are wanted for different things: every handshake
        frame is worth annotating in the capture, while only the one that
        completes a set is worth interrupting the operator for.

        Completion is reported once. A network that re-keys sends another
        handshake, and a warning per re-key trains the reader to ignore it.
        """
        found = parse_eapol_key(frame)
        if found is None:
            return None, None
        key = (found.bssid, found.station)
        handshake = self.handshakes.get(key)
        if handshake is None:
            handshake = self.handshakes[key] = Handshake(found.bssid,
                                                         found.station)
        handshake.messages.add(found.message)
        if handshake.complete and key not in self._reported:
            self._reported.add(key)
            return found, handshake
        return found, None

    @property
    def complete_count(self) -> int:
        return sum(1 for h in self.handshakes.values() if h.complete)

    @property
    def partial(self) -> list[Handshake]:
        """Started and not finished, which is worth saying: it means the
        capture caught part of a join and a little longer might catch all of
        it."""
        return [h for h in self.handshakes.values() if not h.complete]
