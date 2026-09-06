"""Recognising the WPA2 four-way handshake.

Tested against constructed frames rather than a capture, because the handshake
happens only when a device joins and cannot be produced on demand -- which is
the whole reason for detecting it.
"""

import struct

from esp32c6_sniffer.eapol import (
    ETHERTYPE_EAPOL,
    KEY_INFO_ACK,
    KEY_INFO_INSTALL,
    KEY_INFO_MIC,
    KEY_INFO_PAIRWISE,
    KEY_INFO_SECURE,
    HandshakeTracker,
    parse_eapol_key,
)

AP = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
STA = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
AP_TEXT = "aa:bb:cc:dd:ee:ff"
STA_TEXT = "11:22:33:44:55:66"

M1 = KEY_INFO_PAIRWISE | KEY_INFO_ACK
M2 = KEY_INFO_PAIRWISE | KEY_INFO_MIC
M3 = KEY_INFO_PAIRWISE | KEY_INFO_ACK | KEY_INFO_MIC | KEY_INFO_INSTALL | KEY_INFO_SECURE
M4 = KEY_INFO_PAIRWISE | KEY_INFO_MIC | KEY_INFO_SECURE


def frame(info, *, from_ap=True, qos=False, data_length=None,
          descriptor=2, eapol_type=3, ethertype=ETHERTYPE_EAPOL):
    """One 802.11 data frame carrying an EAPOL-Key body."""
    if data_length is None:
        data_length = 0 if info == M4 else 22
    fc0 = (2 << 2) | ((0x08 if qos else 0) << 4)
    fc1 = 0x02 if from_ap else 0x01          # from-DS or to-DS
    if from_ap:
        address1, address2 = STA, AP
    else:
        address1, address2 = AP, STA
    out = bytearray()
    out += bytes([fc0, fc1, 0, 0]) + address1 + address2 + AP + b"\x00\x00"
    if qos:
        out += b"\x00\x00"
    out += b"\xaa\xaa\x03\x00\x00\x00" + struct.pack(">H", ethertype)
    out += bytes([2, eapol_type]) + struct.pack(">H", 95)
    body = bytearray(95)
    body[0] = descriptor
    struct.pack_into(">H", body, 1, info)
    struct.pack_into(">H", body, 93, data_length)
    out += body
    return bytes(out)


def test_each_message_is_identified():
    for info, expected in ((M1, 1), (M2, 2), (M3, 3), (M4, 4)):
        got = parse_eapol_key(frame(info, from_ap=expected in (1, 3)))
        assert got is not None, expected
        assert got.message == expected


def test_the_access_point_is_identified_whichever_way_the_frame_goes():
    """Addressing depends on direction. Reading it one way round pairs each
    message with the wrong conversation, and no handshake ever completes."""
    from_ap = parse_eapol_key(frame(M1, from_ap=True))
    to_ap = parse_eapol_key(frame(M2, from_ap=False))
    assert (from_ap.bssid, from_ap.station) == (AP_TEXT, STA_TEXT)
    assert (to_ap.bssid, to_ap.station) == (AP_TEXT, STA_TEXT)
    assert from_ap.from_ap and not to_ap.from_ap


def test_a_qos_frame_has_a_longer_header():
    """Two extra bytes before the payload. Missing them reads the QoS field as
    the start of the LLC header and rejects a real handshake."""
    assert parse_eapol_key(frame(M1, qos=True)) is not None


def test_the_group_handshake_is_not_counted():
    """It uses the same frames and follows immediately, so counting it would
    report a second four-way that never happened."""
    assert parse_eapol_key(frame(M1 & ~KEY_INFO_PAIRWISE)) is None


def test_a_non_eapol_data_frame_is_rejected():
    assert parse_eapol_key(frame(M1, ethertype=0x0800)) is None


def test_a_non_key_eapol_frame_is_rejected():
    assert parse_eapol_key(frame(M1, eapol_type=1)) is None


def test_an_unknown_key_descriptor_is_rejected():
    assert parse_eapol_key(frame(M1, descriptor=99)) is None


def test_a_management_frame_is_rejected_cheaply():
    beacon = bytes([0x80, 0x00]) + bytes(30)
    assert parse_eapol_key(beacon) is None


def test_a_frame_truncated_by_the_snapshot_length_is_rejected():
    """Rather than read past the end. A 256-byte snaplen keeps a whole
    handshake frame, but a shorter one would not."""
    full = frame(M1)
    for cut in range(0, len(full)):
        parse_eapol_key(full[:cut])      # must not raise


def test_random_input_never_raises():
    import random
    rng = random.Random(20260906)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        parse_eapol_key(blob)


def test_a_complete_handshake_is_reported_once():
    tracker = HandshakeTracker()
    results = [tracker.feed(frame(info, from_ap=info in (M1, M3)))
               for info in (M1, M2, M3, M4)]
    # Every one is recognised as a handshake frame, for annotating the file...
    assert all(r[0] is not None for r in results)
    # ...but only the last completes a set.
    assert [r[1] for r in results[:3]] == [None, None, None]
    assert results[3][1] is not None and results[3][1].complete
    # A re-key sends another; warning every time trains the reader to ignore it.
    assert tracker.feed(frame(M4, from_ap=False))[1] is None


def test_two_stations_joining_at_once_are_not_confused():
    """Interleaved messages from two devices would otherwise look like one
    complete handshake belonging to neither."""
    global STA, STA_TEXT
    tracker = HandshakeTracker()
    first = [frame(info, from_ap=info in (M1, M3)) for info in (M1, M2)]
    original, original_text = STA, STA_TEXT
    STA = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
    STA_TEXT = "de:ad:be:ef:00:01"
    second = [frame(info, from_ap=info in (M1, M3)) for info in (M1, M2, M3, M4)]
    STA, STA_TEXT = original, original_text

    for f in (first[0], second[0], first[1], second[1], second[2]):
        assert tracker.feed(f)[1] is None
    done = tracker.feed(second[3])[1]
    assert done is not None
    assert done.station == "de:ad:be:ef:00:01"
    assert tracker.complete_count == 1
    assert len(tracker.partial) == 1


def test_a_partial_handshake_is_visible():
    tracker = HandshakeTracker()
    tracker.feed(frame(M1))
    tracker.feed(frame(M2, from_ap=False))
    assert tracker.complete_count == 0
    assert len(tracker.partial) == 1
    assert tracker.partial[0].messages == {1, 2}
