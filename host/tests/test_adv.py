"""Advertising report decoding, including the two layouts that differ."""

import struct

from esp32c6_sniffer.adv import (
    META_LEN,
    AddressType,
    parse_ad_structures,
    parse_advertising_reports,
)

MAC = bytes([0x66, 0x55, 0x44, 0x33, 0x22, 0x11])   # least significant first
MAC_TEXT = "11:22:33:44:55:66"


def meta(hci: bytes) -> bytes:
    return struct.pack("<QHBB", 1, len(hci), 0, 0) + hci


def legacy(data: bytes, rssi=0xC0, address=MAC, address_type=0x00,
           reports=1) -> bytes:
    body = bytearray([reports])
    for _ in range(reports):
        body += bytes([0x00, address_type]) + address
        body += bytes([len(data)]) + data + bytes([rssi])
    return meta(bytes([0x04, 0x3E, len(body) + 1, 0x02]) + bytes(body))


def extended(data: bytes, rssi=0xC0, address=MAC, address_type=0x01,
             event_type=0x0000) -> bytes:
    body = bytearray([1])
    body += bytes([event_type & 0xFF, event_type >> 8, address_type]) + address
    body += bytes([0x01, 0x00, 0x00, 0x7F, rssi])     # PHYs, SID, TX, RSSI
    body += bytes([0x00, 0x00])                        # periodic interval
    body += bytes([0x00]) + bytes(6)                   # direct address
    body += bytes([len(data)]) + data
    return meta(bytes([0x04, 0x3E, len(body) + 1, 0x0D]) + bytes(body))


def ad(*structures: tuple[int, bytes]) -> bytes:
    out = bytearray()
    for ad_type, value in structures:
        out += bytes([len(value) + 1, ad_type]) + value
    return bytes(out)


def test_legacy_report_decodes():
    reports = parse_advertising_reports(legacy(ad((0x09, b"kettle"))))
    assert len(reports) == 1
    report = reports[0]
    assert report.address == MAC_TEXT
    assert report.name == "kettle"
    assert report.rssi_dbm == -64
    assert not report.via_extended_report
    assert not report.extended_pdu


def test_extended_report_decodes_with_its_own_layout():
    """The RSSI sits before the data here and after it in the legacy layout;
    reading one with the other's offsets yields an address belonging to
    nobody."""
    reports = parse_advertising_reports(extended(ad((0x09, b"speaker"))))
    assert len(reports) == 1
    assert reports[0].address == MAC_TEXT
    assert reports[0].name == "speaker"
    assert reports[0].rssi_dbm == -64
    assert reports[0].via_extended_report
    assert reports[0].extended_pdu


def test_multiple_reports_in_one_event():
    reports = parse_advertising_reports(legacy(ad((0x09, b"x")), reports=3))
    assert len(reports) == 3


def test_manufacturer_data_names_a_company():
    reports = parse_advertising_reports(
        legacy(ad((0xFF, bytes([0x4C, 0x00]) + b"payload"))))
    assert reports[0].company_id == 0x004C
    assert reports[0].company == "Apple"


def test_unknown_company_is_a_number_not_a_guess():
    reports = parse_advertising_reports(
        legacy(ad((0xFF, bytes([0x34, 0x12])))))
    assert reports[0].company == "0x1234"


def test_address_privacy_is_classified():
    """A resolvable private address rotates, so counting it as a device counts
    one phone many times over."""
    resolvable = bytes([1, 2, 3, 4, 5, 0x40 | 0x0A])
    static = bytes([1, 2, 3, 4, 5, 0xC0 | 0x0A])
    assert AddressType.classify(0x00, MAC) == AddressType.PUBLIC
    assert AddressType.classify(0x01, resolvable) == \
        AddressType.RANDOM_RESOLVABLE
    assert AddressType.classify(0x01, static) == AddressType.RANDOM_STATIC


def test_only_stable_addresses_count_as_trackable():
    public = parse_advertising_reports(legacy(b"", address_type=0x00))[0]
    resolvable = parse_advertising_reports(
        legacy(b"", address_type=0x01,
               address=bytes([1, 2, 3, 4, 5, 0x40])))[0]
    assert public.trackable
    assert not resolvable.trackable


def test_zero_padding_ends_the_structures():
    """Advertising data is padded with zeros, which is normal termination and
    must not be read as a structure of length zero forever."""
    assert parse_ad_structures(ad((0x09, b"hi")) + bytes(20)) == [(0x09, b"hi")]


def test_a_structure_running_past_the_end_is_dropped_not_raised():
    assert parse_ad_structures(bytes([40, 0x09]) + b"short") == []


def test_a_name_with_invalid_utf8_does_not_raise():
    reports = parse_advertising_reports(legacy(ad((0x09, b"caf\xff"))))
    assert reports[0].name.startswith("caf")


def test_a_non_advertising_event_yields_nothing():
    assert parse_advertising_reports(meta(bytes([0x04, 0x0E, 0x04, 1, 3, 12, 0]))) == []


def test_truncated_reports_yield_what_parsed_cleanly():
    full = legacy(ad((0x09, b"kettle")))
    for cut in range(META_LEN, len(full)):
        parse_advertising_reports(full[:cut])      # must not raise


def test_random_input_never_raises():
    import random
    rng = random.Random(20260906)
    for _ in range(3000):
        blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
        for report in parse_advertising_reports(blob):
            assert isinstance(report.address, str)
            report.company
            report.trackable


def test_a_legacy_advertisement_seen_through_extended_scanning_is_not_extended():
    """Extended scanning reports legacy advertisements too, with a bit set to
    say so. Reading the report format instead of that bit made every device
    look like a BLE 5 device, which is a statistic about nothing."""
    from esp32c6_sniffer.adv import EVENT_TYPE_LEGACY_PDU
    reports = parse_advertising_reports(
        extended(ad((0x09, b"old")), event_type=EVENT_TYPE_LEGACY_PDU))
    assert reports[0].via_extended_report      # it came the extended way
    assert not reports[0].extended_pdu         # but it is a legacy advert


def test_a_genuine_extended_advertisement_is_flagged():
    reports = parse_advertising_reports(
        extended(ad((0x09, b"new")), event_type=0x0000))
    assert reports[0].via_extended_report
    assert reports[0].extended_pdu
