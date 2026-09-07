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
