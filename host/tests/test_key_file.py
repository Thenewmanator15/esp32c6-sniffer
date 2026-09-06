"""Zigbee key files, which are refused loudly rather than accepted wrongly.

A key that is subtly wrong -- a digit short, the wrong kind, pasted with a
stray character -- produces a capture that simply does not decrypt. Hunting
that afterwards, with the traffic long gone, is far worse than being told at
the point of typing it. So every failure here names the line.

The key is read from a file rather than an option value because an extcap
argument reaches the process list and Wireshark's saved configuration.
"""

import importlib.util
from pathlib import Path

import pytest

from esp32c6_sniffer.pcapng import SECRET_ZIGBEE_APS, SECRET_ZIGBEE_NWK

PLUGIN = Path(__file__).resolve().parents[2] / "extcap" / "esp32c6-sniffer.py"


def load_plugin():
    """The plugin's filename has a dash, so it cannot simply be imported."""
    spec = importlib.util.spec_from_file_location("extcap_plugin", PLUGIN)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


plugin = load_plugin()


def keyfile(tmp_path, text):
    path = tmp_path / "keys.txt"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_a_labelled_network_key_is_read(tmp_path):
    keys = plugin.read_key_file(
        keyfile(tmp_path, "nwk 000102030405060708090a0b0c0d0e0f\n"))
    assert keys == [(SECRET_ZIGBEE_NWK, bytes(range(16)))]


def test_an_application_key_is_read(tmp_path):
    keys = plugin.read_key_file(
        keyfile(tmp_path, "aps 000102030405060708090a0b0c0d0e0f\n"))
    assert keys[0][0] == SECRET_ZIGBEE_APS


def test_an_unlabelled_key_is_taken_as_a_network_key(tmp_path):
    """Which is the one almost everybody means."""
    keys = plugin.read_key_file(
        keyfile(tmp_path, "000102030405060708090a0b0c0d0e0f\n"))
    assert keys == [(SECRET_ZIGBEE_NWK, bytes(range(16)))]


def test_colons_are_allowed(tmp_path):
    """Border routers print keys both ways."""
    text = ":".join(f"{b:02x}" for b in range(16))
    keys = plugin.read_key_file(keyfile(tmp_path, text))
    assert keys[0][1] == bytes(range(16))


def test_comments_and_blank_lines_are_ignored(tmp_path):
    keys = plugin.read_key_file(keyfile(tmp_path, (
        "# the living-room network\n"
        "\n"
        "nwk 000102030405060708090a0b0c0d0e0f   # rotated 2026-08\n"
        "\n")))
    assert len(keys) == 1


def test_several_keys_are_all_returned(tmp_path):
    keys = plugin.read_key_file(keyfile(tmp_path, (
        "nwk 000102030405060708090a0b0c0d0e0f\n"
        "aps 0f0e0d0c0b0a09080706050403020100\n")))
    assert [k[0] for k in keys] == [SECRET_ZIGBEE_NWK, SECRET_ZIGBEE_APS]


@pytest.mark.parametrize("text,expected", [
    ("nwk 000102030405060708090a0b0c0d0e\n", "16 bytes"),      # a byte short
    ("nwk 000102030405060708090a0b0c0d0e0f00\n", "16 bytes"),  # a byte over
    ("nwk not-hexadecimal-at-all-xyzq\n", "not hexadecimal"),
    ("link 000102030405060708090a0b0c0d0e0f\n", "unknown key kind"),
])
def test_a_bad_key_is_refused_with_the_line_number(tmp_path, text, expected):
    with pytest.raises(ValueError) as caught:
        plugin.read_key_file(keyfile(tmp_path, text))
    message = str(caught.value)
    assert expected in message
    assert "line 1" in message


def test_the_reported_line_number_is_the_offending_one(tmp_path):
    with pytest.raises(ValueError) as caught:
        plugin.read_key_file(keyfile(tmp_path, (
            "# comment\n"
            "nwk 000102030405060708090a0b0c0d0e0f\n"
            "nwk deadbeef\n")))
    assert "line 3" in str(caught.value)


def test_an_empty_file_is_refused(tmp_path):
    """Silently capturing without the key the user asked for would look like
    a decryption failure rather than a missing key."""
    with pytest.raises(ValueError, match="no keys"):
        plugin.read_key_file(keyfile(tmp_path, "# nothing here\n"))


def test_a_missing_file_is_refused_by_name(tmp_path):
    with pytest.raises(ValueError, match="cannot read key file"):
        plugin.read_key_file(str(tmp_path / "absent.txt"))
