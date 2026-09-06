"""BLE records: the pseudo-header, and refusing to guess at HCI."""

import struct

import pytest

from esp32c6_sniffer.ble import (
    EVENT_LE_META,
    H4_EVENT,
    LE_SUBEVENT_ADV_REPORT,
    LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR,
    META_LEN,
    advertiser_address,
    build_ble_record,
    is_advertising_report,
)

META = struct.Struct("<QHBB")


def frame(hci: bytes, timestamp=1234, flags=0) -> bytes:
    return META.pack(timestamp, len(hci), flags, 0) + hci


def adv_report(address=b"\x06\x05\x04\x03\x02\x01", reports=1) -> bytes:
    """A minimal legacy LE Advertising Report."""
    body = bytes([reports, 0x00, 0x01]) + address + bytes([0x00, 0x00])
    return bytes([H4_EVENT, EVENT_LE_META, len(body) + 1,
                  LE_SUBEVENT_ADV_REPORT]) + body


def test_metadata_length_matches_the_firmware_struct():
    assert META_LEN == 12
    assert META.size == META_LEN


def test_record_carries_a_direction_pseudo_header():
    """Plain H4 leaves Wireshark guessing which way a packet went."""
    hci = adv_report()
    record, hci_len, timestamp = build_ble_record(frame(hci, timestamp=99))
    assert timestamp == 99
    assert hci_len == len(hci)
    # Four bytes, big-endian, 1 meaning controller to host.
    assert record[:4] == b"\x00\x00\x00\x01"
    assert record[4:] == hci


def test_link_type_is_the_one_with_a_pseudo_header():
    assert LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR == 201


def test_payload_with_no_hci_at_all_is_rejected():
    """Metadata and nothing else is not a packet, and emitting a record with
    an empty body would look like a real capture of nothing."""
    with pytest.raises(ValueError):
        build_ble_record(META.pack(1, 0, 0, 0))


def test_truncated_payload_is_rejected():
    for cut in range(META_LEN + 1):
        with pytest.raises(ValueError):
            build_ble_record(frame(adv_report())[:cut])


def test_advertising_reports_are_recognised():
    assert is_advertising_report(frame(adv_report()))


def test_a_command_complete_is_not_an_advertising_report():
    hci = bytes([H4_EVENT, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00])
    assert not is_advertising_report(frame(hci))


def test_advertiser_address_is_byte_reversed():
    """HCI carries addresses least significant byte first; they are written
    the other way round, and getting it backwards names the wrong device."""
    address = bytes([0x06, 0x05, 0x04, 0x03, 0x02, 0x01])
    assert advertiser_address(frame(adv_report(address))) == \
        "01:02:03:04:05:06"


def test_multi_report_events_are_not_guessed_at():
    """More than one report per event moves every later field, so returning
    the first address would be a guess dressed as a fact."""
    assert advertiser_address(frame(adv_report(reports=2))) is None


def test_address_of_a_non_advertising_event_is_none():
    hci = bytes([H4_EVENT, 0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00])
    assert advertiser_address(frame(hci)) is None


def test_random_input_never_raises():
    """These decode radio traffic from equipment nobody controls."""
    import random
    rng = random.Random(20260906)
    for _ in range(2000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 64)))
        is_advertising_report(blob)
        advertiser_address(blob)
        try:
            build_ble_record(blob)
        except ValueError:
            pass
