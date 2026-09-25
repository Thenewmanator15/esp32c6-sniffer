"""Installs Zigbee's public default Trust Center link key into Wireshark.

    python tools/zigbee_key.py           add it wherever it is missing
    python tools/zigbee_key.py --list    say how many keys each table holds

The key is public ("ZigBeeAlliance09") and decrypts nothing by itself. With it,
Wireshark reads the key transport a network sends when a device joins, and
derives that network's key -- so capture on the network's channel and put a
device into pairing mode. Your own keys already in the table are left as they
are; the default key is appended, and only where it is missing. Nothing here
prints a key.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from esp32c6_sniffer.zigbee import install_default_key, key_count, key_table_paths  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="Install Zigbee's default Trust Center link key into Wireshark")
    ap.add_argument("--list", action="store_true", help="show how many keys each table holds")
    args = ap.parse_args()

    if args.list:
        for table in key_table_paths():
            n = key_count(table)
            print(f"{table}: {n} key{'' if n == 1 else 's'}")
        return 0

    written = install_default_key()
    if not written:
        print("the default key is already in every table")
        return 0
    print("added the default Trust Center link key to:")
    for table in written:
        print(f"  {table}")
    print()
    print("Restart Wireshark. Then capture on the network's channel and put a")
    print("device into pairing mode: the network key is read from the join.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
