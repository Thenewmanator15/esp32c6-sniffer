"""The names this project relies on still exist in the Wireshark installed here.

The profiles' filter buttons, colouring rules and columns, the key tables the
tools write, and the fields the documentation tells people to filter on are all
names owned by Wireshark. Wireshark's answer to a name it no longer knows is
usually silence: a column stays empty, a button matches nothing, a key row is
ignored. A Wireshark update that renamed one would look exactly like a network
with nothing to show. So each name is put to the installed tshark itself.

Skipped where tshark is not installed (CI, for one). Point WIRESHARK_TSHARK at
a specific tshark to check another version.
"""

from __future__ import annotations

import csv
import functools
import io
import os
import re
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from esp32c6_sniffer.thread import HASH_TYPE_THREAD

REPO = Path(__file__).resolve().parents[2]
PROFILE_ROOT = REPO / "wireshark-profiles"
DOCS = [REPO / "README.md", REPO / "docs" / "using-wireshark.md"]

#: Fields the documentation names ahead of a Wireshark release carrying them:
#: the LE Audio and periodic-advertising patches prepared for upstream. Each
#: entry comes out when a release has it.
PENDING_UPSTREAM = (
    "bluetooth.le_audio.",
    "bthci_evt.periodic_data.",
    "bthci_evt.expert.periodic_data_truncated",
    "btcommon.eir_ad.entry.rsi.",
)


def find_tshark() -> str | None:
    candidates = [os.environ.get("WIRESHARK_TSHARK"), shutil.which("tshark"),
                  r"C:\Program Files\Wireshark\tshark.exe",
                  "/Applications/Wireshark.app/Contents/MacOS/tshark"]
    return next((c for c in candidates if c and Path(c).is_file()), None)


TSHARK = find_tshark()
pytestmark = pytest.mark.skipif(TSHARK is None, reason="tshark is not installed")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([TSHARK, *args], capture_output=True, text=True, timeout=120)


@functools.cache
def glossary() -> tuple[frozenset[str], frozenset[str]]:
    """Every field and protocol filter name tshark knows."""
    fields, protocols = set(), set()
    for line in run("-G", "fields").stdout.splitlines():
        parts = line.split("\t")
        if parts[0] == "F" and len(parts) > 2:
            fields.add(parts[2])
        elif parts[0] == "P" and len(parts) > 2:
            protocols.add(parts[2])
    return frozenset(fields), frozenset(protocols)


@pytest.fixture(scope="module")
def empty_capture(tmp_path_factory) -> Path:
    """A pcap with no packets, so a filter is compiled and nothing else happens."""
    path = tmp_path_factory.mktemp("names") / "empty.pcap"
    path.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 195))
    return path


def compile_error(display_filter: str, capture: Path) -> str | None:
    result = run("-r", str(capture), "-Y", display_filter)
    if result.returncode == 0:
        return None
    lines = [line for line in result.stderr.splitlines()
             if line.strip() and "Epan WARNING" not in line and "preferences" not in line]
    return " / ".join(lines[-3:]) or f"exit {result.returncode}"


def profile_filters() -> list[tuple[str, str]]:
    """(where, filter) for every button, colouring rule and custom column."""
    found = []
    for profile in sorted(p for p in PROFILE_ROOT.iterdir() if p.is_dir()):
        buttons = profile / "dfilter_buttons"
        if buttons.is_file():
            text = "".join(l for l in buttons.read_text(encoding="utf-8").splitlines(True)
                           if not l.lstrip().startswith("#"))
            for row in csv.reader(io.StringIO(text)):
                if len(row) >= 3 and row[2]:
                    found.append((f"{profile.name}/dfilter_buttons {row[1]}", row[2]))
        colours = profile / "colorfilters"
        if colours.is_file():
            for line in colours.read_text(encoding="utf-8").splitlines():
                if line.startswith("@"):
                    _, name, expr, _rest = line.split("@", 3)
                    found.append((f"{profile.name}/colorfilters {name}", expr))
        prefs = profile / "preferences"
        if prefs.is_file():
            for field in re.findall(r"%Cus:([^:\"]+):", prefs.read_text(encoding="utf-8")):
                found.append((f"{profile.name}/preferences column", field))
    return found


def test_the_profiles_name_only_filters_this_wireshark_accepts(empty_capture):
    filters = profile_filters()
    assert filters, "no profile filters found: the parsing here is out of date"
    broken = [f"{where}: {expr!r}: {error}" for where, expr in filters
              if (error := compile_error(expr, empty_capture))]
    assert not broken, "\n".join(broken)


def test_the_decode_as_entry_names_a_table_and_dissector_that_exist():
    entries = (PROFILE_ROOT / "ESP32-C6 802.15.4" / "decode_as_entries").read_text(encoding="utf-8")
    table, _value, _initial, dissector = re.search(
        r"^decode_as_entry:\s*([^,]+),([^,]+),([^,]+),(.+)$", entries, re.MULTILINE).groups()
    tables = {line.split("\t")[0] for line in run("-G", "dissector-tables").stdout.splitlines()}
    assert table in tables
    descriptions = {line.split("\t")[0] for line in run("-G", "protocols").stdout.splitlines()}
    assert dissector.strip() in descriptions


#: Each key table the tools write or the documentation points at, with a row in
#: the exact format used. Keys are all-zero placeholders: only the format is
#: being tested.
KEY_ROWS = {
    "ieee802154_keys": f'"00000000000000000000000000000000","0","{HASH_TYPE_THREAD}"',
    "btmesh_nw_keys": '"0x00000000000000000000000000000000","0x00000000000000000000000000000000","0x00000000"',
}


@pytest.mark.parametrize("table", sorted(KEY_ROWS))
def test_key_tables_exist_and_take_the_rows_written_to_them(table, empty_capture):
    result = run("-o", f"uat:{table}:{KEY_ROWS[table]}", "-r", str(empty_capture))
    assert "Unknown preference" not in result.stderr, f"{table} no longer exists"
    assert result.returncode == 0, result.stderr.strip().splitlines()[-1:]


def code_in(text: str) -> list[str]:
    """The fenced blocks and inline code spans of a Markdown document."""
    blocks = re.findall(r"```.*?```", text, flags=re.DOTALL)
    rest = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    return blocks + re.findall(r"`[^`\n]+`", rest)


def documented_fields() -> set[str]:
    """Dotted names in the documentation's code that start with a protocol.

    Only code is read, where a filter or field is written out to be typed;
    prose mentions protocols in passing and would bring in false matches.
    """
    _fields, protocols = glossary()
    names = set()
    for doc in DOCS:
        for code in code_in(doc.read_text(encoding="utf-8")):
            for token in re.findall(r"(?<![\w.\\/-])([a-z][a-z0-9_-]*(?:\.[a-z0-9_]+)+)(?![\w\\/])", code):
                if token.split(".")[0] in protocols:
                    names.add(token)
    return names


def test_fields_the_documentation_names_exist():
    fields, protocols = glossary()
    named = documented_fields()
    assert named, "no documented field names found: the scan here is out of date"
    missing = sorted(n for n in named
                     if n not in fields and n not in protocols
                     and not n.startswith(PENDING_UPSTREAM))
    assert not missing, "documented but unknown to this Wireshark: " + ", ".join(missing)
