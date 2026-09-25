"""Identity resolving keys: the hash, the key file, and the checks built on
them. Only the Core specification's own sample key appears here; a real key
in a repository would let anyone follow the device it belongs to."""

import pytest

from esp32c6_sniffer.ble_keys import (
    address_bytes,
    aes128_encrypt,
    ah,
    make_rpa,
    normalize_address,
    resolves,
)

#: Core specification v5.4, Vol 3 Part H, 2.2 sample data, written most
#: significant byte first as the specification writes it.
IRK = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
IDENTITY = "de:ad:be:ef:00:01"


def test_aes_matches_fips_197_appendix_c1():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes128_encrypt(key, plain).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes_refuses_the_wrong_sizes():
    with pytest.raises(ValueError):
        aes128_encrypt(bytes(15), bytes(16))
    with pytest.raises(ValueError):
        aes128_encrypt(bytes(16), bytes(17))


def test_ah_matches_the_core_specification_sample():
    assert ah(IRK, 0x708194) == 0x0DFBAA


def test_an_address_made_from_a_key_resolves_with_it():
    for prand in (0x400001, 0x5ABCDE, 0x7FFFFF):
        assert resolves(IRK, make_rpa(IRK, prand))


def test_it_does_not_resolve_with_the_key_reversed():
    assert not resolves(IRK[::-1], make_rpa(IRK, 0x400001))


def test_only_a_resolvable_private_address_can_resolve():
    """Top two bits 11 is static, 00 non-resolvable: neither carries a hash."""
    assert not resolves(IRK, IDENTITY)
    assert not resolves(IRK, "11:22:33:44:55:66")


def test_make_rpa_wants_a_resolvable_prand():
    with pytest.raises(ValueError):
        make_rpa(IRK, 0xC00001)          # top bits 11
    with pytest.raises(ValueError):
        make_rpa(IRK, 1 << 24)


def test_addresses_accept_colons_dashes_and_either_case():
    assert address_bytes("DE-AD-BE-EF-00-01") == bytes.fromhex("deadbeef0001")
    assert normalize_address("DE-AD-BE-EF-00-01") == IDENTITY


@pytest.mark.parametrize("bad", ["", "de:ad:be:ef:00", "de:ad:be:ef:00:01:02",
                                 "zz:ad:be:ef:00:01", "deadbeef0001"])
def test_a_malformed_address_is_refused(bad):
    with pytest.raises(ValueError):
        address_bytes(bad)
