"""Decoding of the access-point records a Wi-Fi scan emits."""

import struct

import pytest

from esp32c6_sniffer.apscan import HEADER_LEN, parse_ap_record

HEADER = struct.Struct("<bBBB6s")


def record(ssid: bytes, *, rssi=-55, channel=6, auth=3,
           bssid=b"\x11\x22\x33\x44\x55\x66", ssid_len=None) -> bytes:
    declared = len(ssid) if ssid_len is None else ssid_len
    return HEADER.pack(rssi, channel, auth, declared, bssid) + ssid


def test_decodes_a_record():
    ap = parse_ap_record(record(b"Example"))
    assert ap.ssid == "Example"
    assert ap.bssid == "11:22:33:44:55:66"
    assert ap.channel == 6
    assert ap.rssi_dbm == -55
    assert ap.auth_name == "WPA2-PSK"
    assert not ap.hidden


def test_negative_rssi_survives_the_round_trip():
    """RSSI is signed; reading it unsigned turns -90 dBm into +166."""
    assert parse_ap_record(record(b"x", rssi=-90)).rssi_dbm == -90


def test_hidden_network_has_an_empty_ssid():
    """A hidden network beacons with an empty SSID rather than none at all."""
    ap = parse_ap_record(record(b""))
    assert ap.hidden
    assert ap.ssid == ""


def test_ssid_with_invalid_utf8_does_not_abort_a_survey():
    """Access points may put anything in an SSID."""
    ap = parse_ap_record(record(b"caf\xff"))
    assert ap.ssid.startswith("caf")


def test_truncated_record_is_rejected():
    assert HEADER_LEN == 10
    with pytest.raises(ValueError):
        parse_ap_record(b"\x00" * 4)


def test_record_claiming_more_ssid_than_it_carries_is_rejected():
    """Better to fail than to report a silently shortened SSID."""
    with pytest.raises(ValueError, match="SSID"):
        parse_ap_record(record(b"abc", ssid_len=20))


def test_unknown_auth_mode_is_named_not_hidden():
    assert parse_ap_record(record(b"x", auth=99)).auth_name == "mode 99"
