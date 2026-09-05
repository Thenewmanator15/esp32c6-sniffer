"""Installs a Thread network key into Wireshark, unlocking Matter traffic.

Matter over Thread is already captured by this sniffer: the frames arrive and
Wireshark identifies them. What it cannot do without a key is read them, because
Thread encrypts at the MAC layer. Supply the network key and the whole stack
opens up: 6LoWPAN, IPv6, UDP, and Matter's own message layer with node
identifiers, session identifiers, counters and acknowledgements.

    python tools/thread_key.py --key 00112233445566778899aabbccddeeff
    python tools/thread_key.py --list

WHAT THIS DOES AND DOES NOT GIVE YOU
------------------------------------
Decrypting the Thread layer reveals the Matter *envelope*: which node talks to
which, session identifiers, message counters, reliability and acknowledgement
behaviour. The Matter *payload* stays encrypted under session keys negotiated
during commissioning, and Wireshark's built-in Matter dissector has no key table
at all, so there is nowhere to supply them. That is a real ceiling, not a
configuration problem.

FINDING YOUR THREAD NETWORK KEY
-------------------------------
It comes from your border router, and only for a network you control:

* Home Assistant: Settings, Devices & Services, Thread, then the overflow menu
  on your border router to view credentials.
* Apple: the Home app can share Thread credentials to a Mac; they then appear
  in Keychain Access.
* Google Home: available through the Google Home Developer Console.
* OpenThread border router: `ot-ctl networkkey`.

The key format Wireshark wants is 32 hexadecimal characters, with or without
separators. This tool accepts both and normalises.

The key is written to Wireshark's own configuration and applies to every
capture, including ones already saved. Delete the line to undo.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# Determined empirically against Wireshark 4.6.8: the table takes three fields,
# and the hash type must be a text label. A numeric value is rejected with
# "invalid value", and omitting it with "expecting field hash_type".
HASH_TYPE_THREAD = "Thread hash"
HASH_TYPE_NONE = "No hash"

HEADER = """# IEEE 802.15.4 decryption keys.
#
# Written by esp32c6-sniffer tools/thread_key.py. Safe to edit or delete;
# removing a line only stops Wireshark decrypting that network.
#
# Format: "key (32 hex chars)","key index","hash type"
# Thread derives its MAC key from the network key, so Thread entries must use
# the "Thread hash" type. A raw MAC key would use "No hash".
"""


def wireshark_config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if not base:
            raise RuntimeError("APPDATA is not set")
        return Path(base) / "Wireshark"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "wireshark"
    return Path.home() / ".config" / "wireshark"


def normalise_key(raw: str) -> str:
    """Accepts hex with or without separators; returns 32 lowercase hex chars."""
    cleaned = re.sub(r"[\s:.\-]", "", raw).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not re.fullmatch(r"[0-9a-f]{32}", cleaned):
        raise ValueError(
            f"expected 32 hex characters (128 bits), got {len(cleaned)}: {raw!r}"
        )
    return cleaned


def read_entries(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.rstrip("\n")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Install a Thread network key into Wireshark"
    )
    ap.add_argument("--key", help="Thread network key, 32 hex characters")
    ap.add_argument("--index", type=int, default=0, help="key index (default 0)")
    ap.add_argument("--list", action="store_true", help="show installed keys")
    args = ap.parse_args()

    path = wireshark_config_dir() / "ieee802154_keys"
    entries = read_entries(path)

    if args.list or not args.key:
        print(f"key table: {path}")
        if not entries:
            print("  no keys installed")
        for entry in entries:
            print(f"  {entry}")
        if not args.key:
            print()
            print("Pass --key <32 hex chars> to install one. See the module")
            print("docstring for where to find your border router's key.")
        return 0

    try:
        key = normalise_key(args.key)
    except ValueError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    line = f'"{key}","{args.index}","{HASH_TYPE_THREAD}"'
    if line in entries:
        print(f"already installed in {path}")
        return 0
    # Keys accumulate rather than replace: several networks can be decrypted in
    # one capture, and clobbering someone's existing entries would be rude.
    entries.append(line)

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEADER + "\n".join(entries) + "\n", encoding="utf-8")

    print(f"installed into {path}")
    print(f"  {line}")
    print()
    print("Restart Wireshark, then reopen any Thread capture. Frames should")
    print("resolve through 6LoWPAN and IPv6 to UDP, and Matter traffic to its")
    print("message layer. The Matter payload itself stays encrypted under")
    print("session keys, which Wireshark has no way to accept.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
