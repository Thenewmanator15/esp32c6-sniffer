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


# --- Matter commissioning ----------------------------------------------------
#
# A Matter device advertises under service 0xFFF6 only while it is waiting to
# be commissioned: out of the box, after a factory reset, or when put into
# pairing mode. A configured one never appears, which makes seeing one a fact
# worth reporting rather than background noise.
#
# Constructed rather than captured: nothing here is in commissioning mode, and
# putting a real device into it to write a test would be an odd way round.

def matter_service_data(discriminator=0x0F00, vendor=0x1234, product=0x5678,
                        version=0, flags=0x00, opcode=0x00):
    combined = (discriminator & 0x0FFF) | ((version & 0x0F) << 12)
    return bytes([0xF6, 0xFF, opcode,
                  combined & 0xFF, combined >> 8,
                  vendor & 0xFF, vendor >> 8,
                  product & 0xFF, product >> 8,
                  flags])


def test_a_commissionable_device_is_decoded():
    from esp32c6_sniffer.adv import AD_SERVICE_DATA_16

    reports = parse_advertising_reports(
        legacy(ad((AD_SERVICE_DATA_16, matter_service_data()))))
    matter = reports[0].matter
    assert matter is not None
    assert matter.discriminator == 0x0F00
    assert matter.vendor_id == 0x1234
    assert matter.product_id == 0x5678


def test_the_discriminator_is_twelve_bits_and_the_version_the_other_four():
    """They share one 16-bit field. Reading the whole field as the
    discriminator gives a number that is right only when the version is 0."""
    from esp32c6_sniffer.adv import AD_SERVICE_DATA_16

    reports = parse_advertising_reports(legacy(ad((
        AD_SERVICE_DATA_16, matter_service_data(discriminator=0xABC,
                                                version=3)))))
    assert reports[0].matter.discriminator == 0xABC
    assert reports[0].matter.version == 3


def test_the_extended_announcement_flag_is_read():
    from esp32c6_sniffer.adv import AD_SERVICE_DATA_16

    plain = parse_advertising_reports(
        legacy(ad((AD_SERVICE_DATA_16, matter_service_data(flags=0x00)))))
    extended = parse_advertising_reports(
        legacy(ad((AD_SERVICE_DATA_16, matter_service_data(flags=0x02)))))
    assert not plain[0].matter.extended_announcement
    assert extended[0].matter.extended_announcement


def test_another_service_is_not_read_as_matter():
    """Service data is common. Decoding somebody else's as Matter would invent
    a commissionable device that does not exist."""
    from esp32c6_sniffer.adv import AD_SERVICE_DATA_16

    other = bytes([0x0D, 0x18]) + bytes(8)     # 0x180D, heart rate
    reports = parse_advertising_reports(
        legacy(ad((AD_SERVICE_DATA_16, other))))
    assert reports[0].matter is None


def test_an_unknown_opcode_is_not_decoded():
    from esp32c6_sniffer.adv import AD_SERVICE_DATA_16

    reports = parse_advertising_reports(
        legacy(ad((AD_SERVICE_DATA_16, matter_service_data(opcode=0x7F)))))
    assert reports[0].matter is None


def test_truncated_matter_data_is_not_decoded():
    from esp32c6_sniffer.adv import AD_SERVICE_DATA_16

    full = matter_service_data()
    for cut in range(2, len(full)):
        reports = parse_advertising_reports(
            legacy(ad((AD_SERVICE_DATA_16, full[:cut]))))
        assert reports[0].matter is None, cut


def test_an_ordinary_advertisement_has_no_matter_field():
    reports = parse_advertising_reports(legacy(ad((0x09, b"kettle"))))
    assert reports[0].matter is None
