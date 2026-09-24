"""Thread credential reading and key installation.

Every dataset here is synthetic. The key is bytes(range(16)), which is
obviously not a real key, and the network name and PAN are invented -- a real
network key must never reach a repository, and a test fixture is the easiest
place for one to hide.
"""

from __future__ import annotations

import pytest

from esp32c6_sniffer.thread import (
    HASH_TYPE_THREAD,
    ThreadCredentials,
    ThreadKeyError,
    credentials_from_dataset,
    install_key,
    key_table_paths,
    normalise_key,
    parse_dataset,
    read_credentials,
)

FAKE_KEY = bytes(range(16))


def tlv(kind: int, value: bytes) -> bytes:
    return bytes([kind, len(value)]) + value


def dataset(channel: int = 15, pan: int = 0x1234, name: bytes = b"testnet0",
            key: bytes = FAKE_KEY) -> bytes:
    return (
        tlv(0x00, bytes([0]) + channel.to_bytes(2, "big"))
        + tlv(0x01, pan.to_bytes(2, "big"))
        + tlv(0x03, name)
        + tlv(0x05, key)
    )


# --- key normalisation ---------------------------------------------------

# The colon and space forms are built rather than spelled out: a 16-byte key
# written with colons contains 6-byte runs that read as MAC addresses, and
# test_no_private_data.py rightly refuses to distinguish those from a real one.
COLON_FORM = ":".join("%02x" % b for b in FAKE_KEY)
SPACE_FORM = " ".join(FAKE_KEY.hex()[i:i + 4] for i in range(0, 32, 4))


@pytest.mark.parametrize("raw", [
    "000102030405060708090a0b0c0d0e0f",
    COLON_FORM,
    "0x000102030405060708090A0B0C0D0E0F",
    SPACE_FORM,
])
def test_a_key_is_accepted_in_the_forms_people_paste(raw):
    assert normalise_key(raw) == "000102030405060708090a0b0c0d0e0f"


@pytest.mark.parametrize("raw", ["", "00", "zz" * 16, "00" * 15, "00" * 17])
def test_a_key_of_the_wrong_size_or_alphabet_is_refused(raw):
    with pytest.raises(ThreadKeyError):
        normalise_key(raw)


# --- dataset parsing -----------------------------------------------------

def test_a_dataset_yields_its_records_in_order():
    records = parse_dataset(dataset())
    assert [kind for kind, _ in records] == [0x00, 0x01, 0x03, 0x05]


def test_a_truncated_dataset_is_refused_rather_than_partly_used():
    """A short read must not silently install a key from a damaged source."""
    blob = dataset()[:-4]
    with pytest.raises(ThreadKeyError, match="truncated"):
        parse_dataset(blob)


def test_trailing_bytes_are_refused():
    with pytest.raises(ThreadKeyError, match="trailing"):
        parse_dataset(dataset() + b"\x00")


def test_a_dataset_gives_the_channel_which_is_the_useful_part():
    """Capturing Thread on the wrong channel looks exactly like a wrong key,
    so the channel travelling with the key is the point of accepting one."""
    creds = credentials_from_dataset(dataset(channel=26, pan=0xBEEF))
    assert creds.channel == 26
    assert creds.pan_id == 0xBEEF
    assert creds.network_name == "testnet0"
    assert creds.key == FAKE_KEY
    assert creds.from_dataset is True


def test_a_dataset_without_a_key_is_refused():
    blob = tlv(0x00, b"\x00\x00\x0f") + tlv(0x01, b"\x12\x34")
    with pytest.raises(ThreadKeyError, match="no Network Key"):
        credentials_from_dataset(blob)


def test_a_key_of_the_wrong_length_inside_a_dataset_is_refused():
    blob = tlv(0x05, b"\x00" * 8)
    with pytest.raises(ThreadKeyError, match="8 bytes"):
        credentials_from_dataset(blob)


# --- reading from a file -------------------------------------------------

def test_a_bare_key_file_is_read_as_a_key(tmp_path):
    p = tmp_path / "key.txt"
    p.write_text(FAKE_KEY.hex(), encoding="utf-8")
    creds = read_credentials(p)
    assert creds.key == FAKE_KEY
    assert creds.from_dataset is False
    assert creds.channel is None


def test_a_dataset_file_is_recognised_by_its_length(tmp_path):
    p = tmp_path / "dataset.txt"
    p.write_text(dataset().hex(), encoding="utf-8")
    creds = read_credentials(p)
    assert creds.from_dataset is True
    assert creds.channel == 15


def test_comments_and_whitespace_are_ignored(tmp_path):
    """So a saved dataset can say which network it belongs to."""
    p = tmp_path / "dataset.txt"
    p.write_text(
        "# kitchen border router, exported 2026-09-07\n"
        + dataset().hex()[:40] + "\n"
        + dataset().hex()[40:] + "  # rest\n",
        encoding="utf-8",
    )
    assert read_credentials(p).channel == 15


@pytest.mark.parametrize("body,match", [
    ("", "empty"),
    ("# only a comment\n", "empty"),
    ("not hex at all", "not hexadecimal"),
    ("abc", "odd number"),
    ("0011223344", "too short"),
])
def test_a_bad_credentials_file_is_refused_with_a_reason(tmp_path, body, match):
    p = tmp_path / "bad.txt"
    p.write_text(body, encoding="utf-8")
    with pytest.raises(ThreadKeyError, match=match):
        read_credentials(p)


def test_a_missing_file_names_itself(tmp_path):
    with pytest.raises(ThreadKeyError, match="cannot read"):
        read_credentials(tmp_path / "nope.txt")


# --- the key must never be printable -------------------------------------

def test_the_key_never_appears_in_a_repr_or_summary():
    """These objects reach error paths and log lines."""
    creds = credentials_from_dataset(dataset())
    for text in (repr(creds), creds.summary(), str(creds)):
        assert FAKE_KEY.hex() not in text
        assert "000102" not in text
    assert "redacted" in repr(creds)
    assert "channel 15" in creds.summary()


def test_the_summary_names_the_network_so_the_right_one_is_confirmable():
    creds = credentials_from_dataset(dataset(channel=20, pan=0xABCD))
    summary = creds.summary()
    assert "testnet0" in summary
    assert "0xabcd" in summary
    assert "channel 20" in summary
    assert "128-bit key" in summary


# --- installation --------------------------------------------------------

def test_the_key_goes_into_the_root_table_and_every_esp32c6_profile(tmp_path):
    for name in ("ESP32-C6 802.15.4", "ESP32-C6 BLE", "Someone Else's"):
        (tmp_path / "profiles" / name).mkdir(parents=True)
    paths = key_table_paths(tmp_path)
    assert [p.parent.name for p in paths] == [
        tmp_path.name, "ESP32-C6 802.15.4", "ESP32-C6 BLE",
    ]


def test_installing_writes_a_thread_hash_entry_everywhere(tmp_path):
    (tmp_path / "profiles" / "ESP32-C6 802.15.4").mkdir(parents=True)
    written = install_key(FAKE_KEY, root=tmp_path)
    assert len(written) == 2
    for table in written:
        text = table.read_text(encoding="utf-8")
        assert f'"{FAKE_KEY.hex()}","0","{HASH_TYPE_THREAD}"' in text


def test_installing_twice_changes_nothing_the_second_time(tmp_path):
    assert install_key(FAKE_KEY, root=tmp_path)
    assert install_key(FAKE_KEY, root=tmp_path) == []


def test_a_second_network_is_added_rather_than_replacing_the_first(tmp_path):
    """One capture can hold two networks; clobbering would be rude."""
    other = bytes(range(16, 32))
    install_key(FAKE_KEY, root=tmp_path)
    install_key(other, root=tmp_path)
    text = (tmp_path / "ieee802154_keys").read_text(encoding="utf-8")
    assert FAKE_KEY.hex() in text
    assert other.hex() in text


def test_an_existing_hand_written_entry_survives(tmp_path):
    table = tmp_path / "ieee802154_keys"
    table.write_text('"ffffffffffffffffffffffffffffffff","3","No hash"\n',
                     encoding="utf-8")
    install_key(FAKE_KEY, root=tmp_path)
    text = table.read_text(encoding="utf-8")
    assert "ffffffffffffffffffffffffffffffff" in text
    assert FAKE_KEY.hex() in text


def test_the_key_index_is_carried_through(tmp_path):
    install_key(FAKE_KEY, index=3, root=tmp_path)
    text = (tmp_path / "ieee802154_keys").read_text(encoding="utf-8")
    assert f'"{FAKE_KEY.hex()}","3","{HASH_TYPE_THREAD}"' in text


def test_credentials_can_be_built_directly_without_a_dataset():
    creds = ThreadCredentials(key=FAKE_KEY)
    assert creds.channel is None
    assert creds.from_dataset is False
    assert "redacted" in repr(creds)


# --- Short-to-long address mappings -----------------------------------------
#
# A sleepy Thread device polls and sends from its 16-bit address, and 802.15.4
# security takes the 64-bit address into the nonce, so Wireshark decrypts its
# frames only once it has learned the pairing. It learns it from MLE
# link-setup messages, which such a device sends only when it attaches: over
# 30 minutes of one network, 1394 frames from 4 sleepy devices stayed
# encrypted. The border router's child table has the pairings; written into
# Wireshark's Static Addresses table they decrypt everything (measured: 0
# frames without the rows, 418 with them, for three mappings).

from esp32c6_sniffer.thread import (  # noqa: E402
    ThreadAddressError,
    address_table_paths,
    install_addresses,
    parse_child_table,
)

CHILD_TABLE = """\
| ID  | RLOC16 | Timeout    | Age        | LQ In | C_VN |R|D|N|Ver|CSL|QMsgCnt|Suppress| Extended MAC     |
+-----+--------+------------+------------+-------+------+-+-+-+---+---+-------+--------+------------------+
|   1 | 0x1c01 |        240 |         24 |     3 |  131 |1|0|0|  3| 0 |     0 |      0 | 1122334455667788 |
|   2 | 0x1c02 |        240 |          2 |     3 |  131 |0|0|0|  4| 1 |     0 |      0 | 0011223344556677 |
Done
"""


def test_an_ot_ctl_child_table_gives_its_pairings():
    assert parse_child_table(CHILD_TABLE) == [
        (0x1C01, 0x1122334455667788),
        (0x1C02, 0x0011223344556677),
    ]


def test_plain_pairs_are_accepted_too():
    text = "# my sensors\n0x1c01 11:22:33:44:55:66:77:88\n1c02,0011223344556677\n"
    assert parse_child_table(text) == [(0x1C01, 0x1122334455667788),
                                       (0x1C02, 0x0011223344556677)]


@pytest.mark.parametrize("text", [
    "0x1c01\n",                          # no extended address
    "0x1c01 11223344556677\n",           # seven octets
    "0xfffe 1122334455667788\n",         # not a unicast short address
    "",                                  # nothing at all
])
def test_a_table_that_does_not_read_is_refused(text):
    with pytest.raises(ThreadAddressError):
        parse_child_table(text)


def test_mappings_go_where_the_keys_go(tmp_path):
    (tmp_path / "profiles" / "ESP32-C6 802.15.4").mkdir(parents=True)
    paths = address_table_paths(tmp_path)
    assert [p.name for p in paths] == ["802154_addresses", "802154_addresses"]
    assert paths[1].parent.name == "ESP32-C6 802.15.4"


def test_installed_rows_are_in_the_format_wireshark_takes(tmp_path):
    written = install_addresses([(0x1C01, 0x1122334455667788)], pan=0x1234, root=tmp_path)
    assert written == [tmp_path / "802154_addresses"]
    rows = [l for l in written[0].read_text(encoding="utf-8").splitlines()
            if l and not l.startswith("#")]
    # Strings quoted, the EUI-64 a bare hex buffer: quoted, Wireshark refuses it.
    assert rows == ['"0x1c01","0x1234",1122334455667788']


def test_installing_mappings_twice_changes_nothing(tmp_path):
    install_addresses([(0x1C01, 0x1122334455667788)], pan=0x1234, root=tmp_path)
    assert install_addresses([(0x1C01, 0x1122334455667788)], pan=0x1234, root=tmp_path) == []
