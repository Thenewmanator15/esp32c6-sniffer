"""Restricting BLE scanning to chosen advertisers.

The controller does the filtering, so a rejected advertisement is never
reported and never crosses the USB link. That matters more than it sounds:
a survey here heard 1927 reports in 45 s and 868 of them were one device
advertising at 21 a second.
"""

import pytest

from esp32c6_sniffer.control import (
    BLE_ADDRESS_PUBLIC,
    BLE_ADDRESS_RANDOM,
    MAX_BLE_FILTER,
    encode_ble_filter,
)
from esp32c6_sniffer.framing import FrameType, decode_frame

ADDRESS = "aa:bb:cc:dd:ee:ff"
#: HCI carries an address least significant byte first.
ON_THE_WIRE = bytes([0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA])


def payload_of(frame: bytes) -> bytes:
    decoded = decode_frame(frame)
    assert decoded.ftype is FrameType.BLE_FILTER
    return decoded.payload


def test_one_address_is_seven_bytes():
    payload = payload_of(encode_ble_filter([ADDRESS]))
    assert len(payload) == 7
    assert payload[0] == BLE_ADDRESS_PUBLIC
    assert payload[1:] == ON_THE_WIRE


def test_the_address_goes_out_least_significant_byte_first():
    """HCI's order. Backwards, the controller filters on an address belonging
    to nobody and reports nothing, which looks exactly like a quiet room."""
    payload = payload_of(encode_ble_filter([ADDRESS]))
    assert payload[1:] == ON_THE_WIRE
    assert payload[1:] != bytes.fromhex(ADDRESS.replace(":", ""))


def test_the_address_type_can_be_given():
    payload = payload_of(
        encode_ble_filter([(BLE_ADDRESS_RANDOM, "11:22:33:44:55:66")]))
    assert payload[0] == BLE_ADDRESS_RANDOM


def test_public_is_assumed_when_no_type_is_given():
    assert payload_of(encode_ble_filter([ADDRESS]))[0] == BLE_ADDRESS_PUBLIC


def test_several_addresses_are_concatenated():
    payload = payload_of(encode_ble_filter([ADDRESS, "11:22:33:44:55:66"]))
    assert len(payload) == 14


def test_an_empty_list_clears_the_filter():
    """Rather than being refused: clearing is how you go back to scanning
    everything, and the firmware reads an empty payload that way."""
    assert payload_of(encode_ble_filter([])) == b""


def test_dashes_are_accepted():
    assert payload_of(encode_ble_filter(["aa-bb-cc-dd-ee-ff"]))[1:] == ON_THE_WIRE


def test_more_than_the_controller_holds_is_refused():
    """The accept list every controller must support is eight. Asking for more
    silently drops the surplus, so it fails here where the caller is told."""
    with pytest.raises(ValueError, match="accept list"):
        encode_ble_filter([ADDRESS] * (MAX_BLE_FILTER + 1))


def test_exactly_the_limit_is_allowed():
    assert len(payload_of(encode_ble_filter([ADDRESS] * MAX_BLE_FILTER))) == 56


@pytest.mark.parametrize("bad", [
    "not-an-address",
    "11:22:33:44:55",            # five bytes
    "11:22:33:44:55:66:77",      # seven
    "gg:22:33:44:55:66",         # not hexadecimal
])
def test_a_malformed_address_is_refused(bad):
    with pytest.raises(ValueError):
        encode_ble_filter([bad])


def test_an_unknown_address_type_is_refused():
    with pytest.raises(ValueError, match="address type"):
        encode_ble_filter([(2, ADDRESS)])
