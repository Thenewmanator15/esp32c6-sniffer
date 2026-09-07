"""Installs Thread credentials into Wireshark, so Thread and Matter decrypt.

Thread encrypts at the MAC layer, so without the network key a capture is a
wall of "Encrypted payload". With it, frames resolve through 6LoWPAN and IPv6
to UDP -- and, with the ESP32-C6 802.15.4 profile's Decode As entry, on to
Matter messages with their session identifiers, counters and acknowledgements.

    python tools/thread_key.py --key-file dataset.txt
    python tools/thread_key.py --list

GIVE IT THE WHOLE DATASET, NOT JUST THE KEY
-------------------------------------------
A border router hands out an *operational dataset*: a hex string carrying the
key, the channel, the PAN ID and the network name together. This tool takes
either that or a bare 32-hex key, and the dataset is worth preferring, because
it tells you which channel to capture on. Sitting on the wrong 802.15.4 channel
produces an empty capture that looks exactly like a wrong key.

WHERE TO FIND IT
----------------
Only for a network you control:

* Home Assistant: Settings, Devices & Services, Thread, then the overflow menu
  on your border router to view credentials. It gives you the dataset.
* Apple: the Home app can share Thread credentials to a Mac; they then appear
  in Keychain Access.
* Google Home: available through the Google Home Developer Console.
* OpenThread border router: `ot-ctl dataset active -x` for the dataset, or
  `ot-ctl networkkey` for the key alone.

WHY A FILE AND NOT AN ARGUMENT
------------------------------
A command-line argument reaches the process list and your shell history, and on
a shared machine that is enough. `--key` still exists for scripting, but
`--key-file` is the one to use. Nothing here ever prints the key.

WHAT THIS CANNOT DO
-------------------
Put the key inside the capture. Wireshark's Decryption Secrets Blocks have
consumers for TLS, SSH, WireGuard, OPC UA and ESP only -- there is no 802.15.4
type at all -- so the key has to live in Wireshark's own configuration. That is
why this writes to Wireshark rather than to your capture file, and why the
capture will not decrypt on someone else's machine unless they do the same.

The Matter *payload* also stays encrypted, under session keys negotiated during
commissioning. Wireshark's Matter dissector has no key table and no
preferences, so there is nowhere to supply them. Session establishment is the
exception: it travels on the unsecured session in clear text, which the
profile's "Commissioning" button selects.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from esp32c6_sniffer.thread import (  # noqa: E402
    ThreadCredentials,
    ThreadKeyError,
    install_key,
    key_table_paths,
    normalise_key,
    read_credentials,
    read_entries,
)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Install Thread credentials into Wireshark"
    )
    ap.add_argument("--key-file", dest="key_file",
                    help="file holding the operational dataset, or a bare "
                         "32-hex network key. Preferred: a path does not "
                         "reach the process list or your shell history")
    ap.add_argument("--key", help="network key as 32 hex characters. Reaches "
                                  "the process list; prefer --key-file")
    ap.add_argument("--index", type=int, default=0, help="key index (default 0)")
    ap.add_argument("--list", action="store_true", help="show installed keys")
    args = ap.parse_args()

    if args.list or (not args.key and not args.key_file):
        for table in key_table_paths():
            print(f"key table: {table}")
            found = read_entries(table)
            if not found:
                print("  no keys installed")
            for entry in found:
                print(f"  {entry}")
        if not args.key and not args.key_file:
            print()
            print("Pass --key-file <path> to install one. See the module")
            print("docstring for where your border router keeps it.")
        return 0

    if args.key and args.key_file:
        sys.stderr.write("error: give --key or --key-file, not both\n")
        return 1

    try:
        if args.key_file:
            creds = read_credentials(args.key_file)
        else:
            creds = ThreadCredentials(key=bytes.fromhex(normalise_key(args.key)))
    except ThreadKeyError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1

    print(f"read {creds.summary()}")
    if creds.from_dataset and creds.channel is not None:
        print(f"capture on channel {creds.channel} -- the wrong channel gives")
        print("an empty capture that looks just like a wrong key")

    written = install_key(creds.key, args.index)
    if not written:
        print("already installed in every key table")
        return 0

    print("installed into:")
    for table in written:
        print(f"  {table}")
    print()
    print("Restart Wireshark, then reopen any Thread capture.")
    print()
    print("Two limits worth knowing, both measured rather than assumed:")
    print("  * Matter needs the ESP32-C6 802.15.4 profile as well as the key.")
    print("    Its dissector claims no UDP port, so without the profile's")
    print("    Decode As entry the frames decrypt and then stop at UDP.")
    print("  * Frames carrying only a short 16-bit source address cannot be")
    print("    decrypted by anyone: the 64-bit address is part of the CCM*")
    print("    nonce. In practice these are sleepy-device Data Requests with")
    print("    no payload, so little is lost.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
