"""thread_key.py's --child-table option, which fills Wireshark's Static
Addresses table so sleepy Thread devices' frames decrypt.

Every run here writes into a temporary configuration directory: APPDATA and
XDG_CONFIG_HOME are pointed at it, so the real Wireshark configuration of
whoever runs the tests is never touched.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "thread_key.py"

CHILD_TABLE = """\
| ID  | RLOC16 | Timeout    | Age        | LQ In | C_VN |R|D|N|Ver|CSL|QMsgCnt|Suppress| Extended MAC     |
+-----+--------+------------+------------+-------+------+-+-+-+---+---+-------+--------+------------------+
|   1 | 0x1c01 |        240 |         24 |     3 |  131 |1|0|0|  3| 0 |     0 |      0 | 1122334455667788 |
Done
"""


@pytest.fixture
def tool(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    spec = importlib.util.spec_from_file_location("thread_key_tool", TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_table(tmp_path: Path) -> Path:
    for candidate in (tmp_path / "Wireshark", tmp_path / "wireshark"):
        if (candidate / "802154_addresses").is_file():
            return candidate / "802154_addresses"
    raise AssertionError("no address table written")


def test_a_child_table_and_a_pan_fill_the_static_addresses_table(tool, tmp_path, monkeypatch, capsys):
    table = tmp_path / "children.txt"
    table.write_text(CHILD_TABLE, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["thread_key.py", "--child-table", str(table), "--pan", "0x1234"])
    assert tool.main() == 0
    rows = [l for l in config_table(tmp_path).read_text(encoding="utf-8").splitlines()
            if l and not l.startswith("#")]
    assert rows == ['"0x1c01","0x1234",1122334455667788']
    out = capsys.readouterr().out
    assert "1 address pair" in out
    # The addresses are the user's devices: said to be installed, not echoed.
    assert "1122334455667788" not in out


def test_a_child_table_without_a_pan_is_refused(tool, tmp_path, monkeypatch, capsys):
    table = tmp_path / "children.txt"
    table.write_text(CHILD_TABLE, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["thread_key.py", "--child-table", str(table)])
    assert tool.main() != 0
    assert "--pan" in capsys.readouterr().err


def test_an_unreadable_child_table_is_refused_with_its_reason(tool, tmp_path, monkeypatch, capsys):
    table = tmp_path / "children.txt"
    table.write_text("0x1c01 not-an-address\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["thread_key.py", "--child-table", str(table), "--pan", "0x1234"])
    assert tool.main() != 0
    assert "64-bit address" in capsys.readouterr().err


def test_listing_the_tables_never_prints_a_key(tool, tmp_path, monkeypatch, capsys):
    """The docstring promises nothing here ever prints the key; --list did."""
    from esp32c6_sniffer.thread import install_key
    key = bytes(range(16))
    install_key(key, root=tmp_path / "Wireshark")
    install_key(key, root=tmp_path / "wireshark")
    monkeypatch.setattr(sys, "argv", ["thread_key.py", "--list"])
    assert tool.main() == 0
    out = capsys.readouterr().out
    assert key.hex() not in out.lower()
    assert "1 key" in out
