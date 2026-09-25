"""Zigbee's public default Trust Center link key, installed into Wireshark.

The key is "ZigBeeAlliance09" in ASCII, published in the Zigbee specification
and shipped with every Zigbee analyser. It decrypts nothing on its own: it lets
Wireshark read the key-transport message a network sends when a device joins,
and from that derive the network's key. Wireshark does not carry it itself.

It is written into Wireshark's own table, `zigbee_pc_keys`, in the root
configuration and every ESP32-C6 profile, as the Thread key is: Wireshark reads
the table per profile. A file there may hold the user's own network keys and
notes, so it is appended to and never rewritten.
"""

from __future__ import annotations

from pathlib import Path

from esp32c6_sniffer.thread import _table_paths, read_entries

DEFAULT_KEY_HEX = "5A6967426565416C6C69616E63653039"
DEFAULT_KEY_ROW = f'"{DEFAULT_KEY_HEX}","Normal","ZigBeeAlliance09"'

HEADER = """# Zigbee decryption keys.
#
# The default Trust Center link key was added by esp32c6-sniffer. It is public
# and decrypts nothing on its own: it lets Wireshark read the key transport
# sent when a device joins, and derive that network's key. Add your own keys
# below it in the same form: "key","Normal","label".
"""


def key_table_paths(root: Path | None = None) -> list[Path]:
    return _table_paths("zigbee_pc_keys", root)


def _key_of(entry: str) -> str:
    """An entry's key, spelled one way: hex digits only, upper case."""
    first = entry.split(",", 1)[0].strip().strip('"')
    return "".join(c for c in first if c not in ":- ").upper()


def key_count(table: Path) -> int:
    return len(read_entries(table))


def install_default_key(root: Path | None = None) -> list[Path]:
    """Adds the default key wherever it is missing, returning the tables changed."""
    written: list[Path] = []
    for table in key_table_paths(root):
        if any(_key_of(entry) == DEFAULT_KEY_HEX for entry in read_entries(table)):
            continue
        if table.is_file():
            text = table.read_text(encoding="utf-8")
            if text and not text.endswith("\n"):
                text += "\n"
            table.write_text(text + DEFAULT_KEY_ROW + "\n", encoding="utf-8")
        else:
            table.parent.mkdir(parents=True, exist_ok=True)
            table.write_text(HEADER + DEFAULT_KEY_ROW + "\n", encoding="utf-8")
        written.append(table)
    return written
