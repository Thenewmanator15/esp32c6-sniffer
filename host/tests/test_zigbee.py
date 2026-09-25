"""Installing Zigbee's public default Trust Center link key into Wireshark.

The README once said the project added it; nothing did. The key is public --
"ZigBeeAlliance09" in ASCII -- and lets Wireshark read the key transport sent
when a device joins, and so derive that network's key. It goes into
Wireshark's own table, next to whatever keys of their own the user keeps
there, which must survive untouched: a file of someone's network keys is not
something to rewrite. Every run here uses a temporary configuration root.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

from esp32c6_sniffer.zigbee import DEFAULT_KEY_ROW, install_default_key, key_count

TOOL = Path(__file__).resolve().parents[1] / "tools" / "zigbee_key.py"


def test_the_row_is_the_one_wireshark_takes():
    # Checked against the installed Wireshark by test_wireshark_names.py.
    assert DEFAULT_KEY_ROW == '"5A6967426565416C6C69616E63653039","Normal","ZigBeeAlliance09"'
    assert bytes.fromhex("5A6967426565416C6C69616E63653039") == b"ZigBeeAlliance09"


def test_it_goes_into_the_root_and_every_esp32c6_profile(tmp_path):
    (tmp_path / "profiles" / "ESP32-C6 802.15.4").mkdir(parents=True)
    (tmp_path / "profiles" / "Someone else's").mkdir(parents=True)
    written = install_default_key(root=tmp_path)
    assert written == [tmp_path / "zigbee_pc_keys",
                       tmp_path / "profiles" / "ESP32-C6 802.15.4" / "zigbee_pc_keys"]
    for table in written:
        assert DEFAULT_KEY_ROW in table.read_text(encoding="utf-8").splitlines()


def test_the_users_own_keys_and_comments_survive(tmp_path):
    table = tmp_path / "zigbee_pc_keys"
    mine = '# my house\n"000102030405060708090A0B0C0D0E0F","Normal","living room"\n'
    table.write_text(mine, encoding="utf-8")
    install_default_key(root=tmp_path)
    text = table.read_text(encoding="utf-8")
    assert text.startswith(mine)
    assert text.splitlines()[-1] == DEFAULT_KEY_ROW


def test_a_file_without_a_final_newline_is_not_joined_onto(tmp_path):
    table = tmp_path / "zigbee_pc_keys"
    table.write_text('"000102030405060708090A0B0C0D0E0F","Normal","mine"', encoding="utf-8")
    install_default_key(root=tmp_path)
    assert table.read_text(encoding="utf-8").splitlines() == [
        '"000102030405060708090A0B0C0D0E0F","Normal","mine"', DEFAULT_KEY_ROW]


@pytest.mark.parametrize("existing", [
    DEFAULT_KEY_ROW,
    # Colon-separated, as Wireshark's own dialog writes it (built here, not
    # typed, so it does not read as a string of MAC addresses).
    '"' + ":".join(b"ZigBeeAlliance09".hex(":").upper().split(":")) + '","Normal","ZigBeeAlliance09"',
    '"5a6967426565416c6c69616e63653039","Normal","already here"',
])
def test_a_key_already_there_in_any_spelling_is_not_added_twice(tmp_path, existing):
    table = tmp_path / "zigbee_pc_keys"
    table.write_text(existing + "\n", encoding="utf-8")
    assert install_default_key(root=tmp_path) == []
    assert table.read_text(encoding="utf-8") == existing + "\n"


def test_keys_are_counted_not_shown(tmp_path):
    table = tmp_path / "zigbee_pc_keys"
    table.write_text('# c\n"000102030405060708090A0B0C0D0E0F","Normal","a"\n' + DEFAULT_KEY_ROW + "\n",
                     encoding="utf-8")
    assert key_count(table) == 2


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("zigbee_key_tool", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_tool_installs_and_then_lists_without_showing_a_key(tool, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["zigbee_key.py"])
    assert tool.main() == 0
    monkeypatch.setattr(sys, "argv", ["zigbee_key.py", "--list"])
    assert tool.main() == 0
    out = capsys.readouterr().out
    assert "1 key" in out
    assert "5A6967426565416C6C69616E63653039" not in out.upper().replace(":", "")
