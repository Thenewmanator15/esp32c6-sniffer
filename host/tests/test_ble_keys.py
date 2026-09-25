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


import base64

from esp32c6_sniffer.ble_keys import (
    KEYCHAIN_BASE64_REVERSED,
    DeviceKey,
    KeyFileError,
    parse_key_file,
)

IRK_HEX = IRK.hex()
IRK_B64 = base64.b64encode(IRK).decode()


def keyfile(tmp_path, text, name="keys.txt", **write):
    path = tmp_path / name
    path.write_text(text, encoding=write.pop("encoding", "utf-8"), **write)
    return path


def test_a_public_identity_with_a_hex_key(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"11:22:33:44:55:66 {IRK_HEX}\n"))
    assert keys == [DeviceKey(1, 0, "11:22:33:44:55:66", IRK)]


def test_a_random_identity_with_a_type_word(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {IRK_HEX}\n"))
    assert (keys[0].address_type, keys[0].address) == (1, IDENTITY)


def test_the_type_word_is_case_insensitive(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} RANDOM {IRK_HEX}\n"))
    assert keys[0].address_type == 1


def test_colons_in_a_hex_key_are_allowed(tmp_path):
    spaced = ":".join(IRK_HEX[i:i + 2] for i in range(0, 32, 2))
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {spaced}\n"))
    assert keys[0].irk == IRK


def test_a_base64_key_is_read_in_the_measured_order(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {IRK_B64}\n"))
    assert keys[0].irk == (IRK[::-1] if KEYCHAIN_BASE64_REVERSED else IRK)


def test_comments_blank_lines_and_line_numbers(tmp_path):
    text = f"# my phone\n\n{IDENTITY} random {IRK_HEX}  # after\n"
    assert parse_key_file(keyfile(tmp_path, text))[0].line == 3


def test_a_notepad_file_with_bom_and_crlf_parses(tmp_path):
    """Review focus 1: Notepad writes a byte-order mark and CRLF."""
    path = tmp_path / "keys.txt"
    path.write_bytes(("# phone\r\n" + f"{IDENTITY} random {IRK_HEX}\r\n")
                     .encode("utf-8-sig"))
    assert parse_key_file(path)[0].address == IDENTITY


def test_a_notepad_unicode_file_parses(tmp_path):
    """Notepad's "Unicode" is UTF-16 with a byte-order mark."""
    path = tmp_path / "keys.txt"
    path.write_bytes(f"# phone\r\n{IDENTITY} random {IRK_HEX}\r\n".encode("utf-16"))
    assert parse_key_file(path)[0].irk == IRK


def test_a_file_in_another_encoding_is_refused_not_a_traceback(tmp_path):
    """An ANSI file with an accented comment used to raise UnicodeDecodeError,
    which reached Wireshark as a Python traceback."""
    path = tmp_path / "keys.txt"
    path.write_bytes(f"# Caf\xe9 iPad\r\n{IDENTITY} random {IRK_HEX}\r\n".encode("cp1252"))
    with pytest.raises(KeyFileError, match="UTF-8"):
        parse_key_file(path)


def test_the_identity_is_normalised(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"DE-AD-BE-EF-00-01 random {IRK_HEX}\n"))
    assert keys[0].address == IDENTITY


def test_the_key_is_not_in_the_repr(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {IRK_HEX}\n"))
    assert IRK_HEX not in repr(keys[0]) and "ec02" not in repr(keys[0])


@pytest.mark.parametrize("line, fragment", [
    (f"{IRK_HEX} {IDENTITY}", "not a BLE address"),     # fields swapped
    (f"{IDENTITY} sideways {IRK_HEX}", "public or random"),
    (f"{IDENTITY} random {IRK_HEX[:-2]}", "32 hex digits"),
    (f"{IDENTITY} random {IRK_HEX} extra", "fields"),
    (f"{IDENTITY} {IRK_HEX} random", "public or random"),  # type after key
    (f"{IDENTITY} random {'0' * 32}", "all-zero"),
    (IRK_HEX, "fields"),
])
def test_a_bad_line_is_refused_by_line_without_echoing_it(tmp_path, line, fragment):
    with pytest.raises(KeyFileError) as caught:
        parse_key_file(keyfile(tmp_path, f"# first\n{line}\n"))
    message = str(caught.value)
    assert "line 2" in message and fragment in message
    for token in line.split():
        if token.lower() in ("public", "random"):
            continue            # the format description names these words
        assert token not in message, "an error message must never echo a field"


def test_a_repeated_identity_is_refused(tmp_path):
    text = f"{IDENTITY} random {IRK_HEX}\nDE:AD:BE:EF:00:01 public {IRK_B64}\n"
    with pytest.raises(KeyFileError, match="line 2.*earlier"):
        parse_key_file(keyfile(tmp_path, text))


def test_more_than_eight_keys_is_refused(tmp_path):
    lines = "".join(f"11:22:33:44:55:{n:02x} {IRK_HEX}\n" for n in range(9))
    with pytest.raises(KeyFileError, match="9 keys"):
        parse_key_file(keyfile(tmp_path, lines))


def test_an_empty_file_is_refused(tmp_path):
    with pytest.raises(KeyFileError, match="no device keys"):
        parse_key_file(keyfile(tmp_path, "# nothing yet\n"))


def test_a_missing_file_is_refused_by_name(tmp_path):
    with pytest.raises(KeyFileError, match="missing.txt"):
        parse_key_file(tmp_path / "missing.txt")


from esp32c6_sniffer.boards import board_by_id
from esp32c6_sniffer.control import MAX_DEVICE_KEYS, encode_ble_keys
from esp32c6_sniffer.framing import FrameType, decode_frame

KEY = DeviceKey(1, 1, IDENTITY, IRK)


def test_the_keys_frame_is_type_15():
    """Pinned: shared/frame.h says 15 too, and both firmwares dispatch on it."""
    assert FrameType.BLE_KEYS == 15
    assert decode_frame(encode_ble_keys([KEY])).ftype is FrameType.BLE_KEYS


def test_one_key_is_23_bytes_least_significant_first():
    payload = decode_frame(encode_ble_keys([KEY])).payload
    assert payload.hex() == (
        "01"                                   # random
        "0100efbeadde"                         # de:ad:be:ef:00:01, LSB first
        "9b7d390aa610103405adc857a33402ec")    # the sample IRK, reversed


def test_an_empty_list_clears_the_keys():
    assert decode_frame(encode_ble_keys([])).payload == b""


def test_more_than_a_frame_holds_is_refused():
    keys = [DeviceKey(n, 0, f"11:22:33:44:55:{n:02x}", IRK)
            for n in range(MAX_DEVICE_KEYS + 1)]
    with pytest.raises(ValueError, match="at most 8"):
        encode_ble_keys(keys)


def test_each_board_says_how_many_keys_it_holds():
    """The C6's resolving list tops out at 5 in its Kconfig; the nRF's is 8."""
    assert board_by_id("esp32c6")["ble_keys"] == 5
    assert board_by_id("nrf54l15")["ble_keys"] == 8


from esp32c6_sniffer.ble_keys import filter_entries


def test_a_keyed_identity_takes_one_entry_of_its_own_type():
    assert filter_entries([IDENTITY], [KEY]) == [(1, IDENTITY)]


def test_a_plain_address_takes_both_types():
    """The measured bug: typed addresses went out as public only, and a
    random-address device was filtered out entirely (0 reports against 10)."""
    assert filter_entries(["11:22:33:44:55:66"], []) == [
        (0, "11:22:33:44:55:66"), (1, "11:22:33:44:55:66")]


def test_the_same_device_typed_twice_takes_its_entries_once():
    """Review focus 2."""
    typed = ["11:22:33:44:55:66", "11-22-33-44-55-66", "11:22:33:44:55:66".upper()]
    assert len(filter_entries(typed, [])) == 2


def test_an_identity_written_differently_still_counts_as_keyed():
    """Review focus 3."""
    assert filter_entries(["DE-AD-BE-EF-00-01"], [KEY]) == [(1, IDENTITY)]


def test_four_plain_addresses_fit_and_five_do_not():
    four = [f"11:22:33:44:55:{n:02x}" for n in range(4)]
    assert len(filter_entries(four, [])) == 8
    with pytest.raises(ValueError, match="holds 8"):
        filter_entries(four + ["de:ad:be:ef:00:01"], [])


def test_eight_keyed_identities_fit():
    keys = [DeviceKey(n, 1, f"de:ad:be:ef:00:{n:02x}", IRK) for n in range(8)]
    assert len(filter_entries([k.address for k in keys], keys)) == 8


from esp32c6_sniffer.ble_keys import (
    KEY_CHECK_SECONDS,
    BackwardsKeyWatch,
    KeyCheck,
    SilenceWatch,
    silence_message,
)


def report(address: str, address_type: int = 1) -> bytes:
    raw = bytes.fromhex(address.replace(":", ""))[::-1]
    body = bytearray([1, 0x10, 0x00, address_type]) + raw
    body += bytes([0x01, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00, 0x00]) + bytes(6)
    body += bytes([0])
    return bytes([0x04, 0x3E, len(body) + 1, 0x0D]) + bytes(body)


BACKWARDS = DeviceKey(2, 1, IDENTITY, IRK[::-1])   # written the wrong way round


def test_a_backwards_key_is_spotted_once():
    watch = BackwardsKeyWatch([BACKWARDS])
    first = watch.observe(report(make_rpa(IRK, 0x400001)))
    assert [(f.key.line, f.reversed) for f in first] == [(2, True)]
    assert watch.observe(report(make_rpa(IRK, 0x400002))) == []


def test_a_correct_key_seen_unresolved_is_a_board_fault():
    [finding] = BackwardsKeyWatch([KEY]).observe(report(make_rpa(IRK, 0x400001)))
    assert not finding.reversed
    assert "board" in finding.message("keys.txt")


def test_resolved_and_static_addresses_are_not_tested():
    watch = BackwardsKeyWatch([BACKWARDS])
    assert watch.observe(report(IDENTITY, address_type=0x03)) == []
    assert watch.observe(report(IDENTITY, address_type=0x01)) == []


def test_the_backwards_message_names_the_line_and_never_the_key():
    [finding] = BackwardsKeyWatch([BACKWARDS]).observe(report(make_rpa(IRK, 0x400001)))
    text = finding.message("keys.txt")
    assert "line 2 of keys.txt" in text and "byte-reversed" in text
    assert IRK.hex() not in text and IRK[::-1].hex() not in text


def test_the_check_counts_distinct_addresses_per_key():
    check = KeyCheck([KEY, BACKWARDS, DeviceKey(3, 0, "11:22:33:44:55:66", bytes(range(1, 17)))])
    for prand in (0x400001, 0x400002, 0x400002):     # one repeated
        check.observe(report(make_rpa(IRK, prand)))
    verdicts = [(r.key.line, r.verdict, r.as_written, r.reversed) for r in check.results()]
    assert verdicts == [(1, "correct", 2, 0), (2, "backwards", 0, 2),
                        (3, "nothing matched", 0, 0)]


def test_check_messages_say_what_to_do():
    check = KeyCheck([BACKWARDS])
    check.observe(report(make_rpa(IRK, 0x400001)))
    [result] = check.results()
    text = result.message("keys.txt")
    assert "line 2" in text and "BACKWARDS" in text and IRK.hex() not in text


def test_the_check_listens_twenty_seconds():
    assert KEY_CHECK_SECONDS == 20.0


def test_silence_is_reported_once_after_thirty_seconds():
    watch = SilenceWatch([IDENTITY], start=100.0)
    assert watch.silent(129.0) == []
    watch.observe(report(IDENTITY, address_type=0x03), at=120.0)
    assert watch.silent(149.0) == []
    assert watch.silent(150.0) == [IDENTITY]
    assert watch.silent(500.0) == []


def test_the_silence_message_suggests_check_keys():
    text = silence_message(IDENTITY, 30.0)
    assert IDENTITY in text and "Check keys" in text
