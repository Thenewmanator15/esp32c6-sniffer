"""Thread credentials: reading them, and installing them where Wireshark looks.

A Thread network key cannot travel inside a capture file. Wireshark defines
Decryption Secrets Block types for TLS, SSH, WireGuard, OPC UA and ESP, and
only those five have a dissector that consumes them; there is no 802.15.4 type
at all. So the only way to make a Thread capture readable is to write the key
into Wireshark's own key table, which is what this module does.

The key is never accepted as a command-line argument, only as a path to a file,
because an argument reaches the process list and Wireshark's saved
configuration. It is never printed, logged, or included in a repr.

WHAT A BORDER ROUTER ACTUALLY GIVES YOU
---------------------------------------
Rarely a bare key. Home Assistant, Apple and the OpenThread border router hand
out an *operational dataset*: a hex string of Meshcop type-length-value records
carrying the key, the channel, the PAN ID and the network name together. That
is more useful than the key alone -- capturing Thread on the wrong channel
looks exactly like a wrong key -- so this module reads either form and, given a
dataset, can tell the caller which channel to sit on.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

#: Wireshark's 802.15.4 key table takes three fields, and the hash type must be
#: a text label matching epan/dissectors/packet-ieee802154.c's value_string. A
#: numeric value is rejected with "invalid value", and omitting it with
#: "expecting field hash_type".
HASH_TYPE_THREAD = "Thread hash"
HASH_TYPE_NONE = "No hash"

#: Meshcop TLV types that appear in an operational dataset. Only the ones worth
#: naming; anything else is reported by number.
TLV_CHANNEL = 0x00
TLV_PAN_ID = 0x01
TLV_EXT_PAN_ID = 0x02
TLV_NETWORK_NAME = 0x03
TLV_PSKC = 0x04
TLV_NETWORK_KEY = 0x05

TLV_NAMES = {
    TLV_CHANNEL: "Channel",
    TLV_PAN_ID: "PAN ID",
    TLV_EXT_PAN_ID: "Extended PAN ID",
    TLV_NETWORK_NAME: "Network Name",
    TLV_PSKC: "PSKc",
    TLV_NETWORK_KEY: "Network Key",
    0x06: "Network Key Sequence",
    0x07: "Mesh Local Prefix",
    0x0C: "Security Policy",
    0x0E: "Active Timestamp",
    0x35: "Channel Mask",
    0x4A: "Delay Timer",
}

#: Both are secrets. Neither is ever rendered.
SECRET_TLVS = frozenset({TLV_PSKC, TLV_NETWORK_KEY})

KEY_BYTES = 16

HEADER = """# IEEE 802.15.4 decryption keys.
#
# Written by esp32c6-sniffer. Safe to edit or delete; removing a line only
# stops Wireshark decrypting that network.
#
# Format: "key (32 hex chars)","key index","hash type"
# Thread derives its MAC key from the network key, so Thread entries must use
# the "Thread hash" type. A raw MAC key would use "No hash".
"""


class ThreadKeyError(ValueError):
    """Raised for anything wrong with a key or dataset, naming what."""


@dataclass
class ThreadCredentials:
    """What was read, with the key held apart from everything printable."""

    key: bytes = field(repr=False)
    channel: int | None = None
    pan_id: int | None = None
    network_name: str | None = None
    #: True when this came from a full operational dataset rather than a bare
    #: key, which is what makes channel and PAN ID trustworthy.
    from_dataset: bool = False

    def __repr__(self) -> str:
        # Explicit, rather than relying on field(repr=False), because this
        # object ends up in error paths and log lines.
        return (
            f"ThreadCredentials(key=<{len(self.key)} bytes, redacted>, "
            f"channel={self.channel}, pan_id={self.pan_id!r}, "
            f"network_name={self.network_name!r}, "
            f"from_dataset={self.from_dataset})"
        )

    def summary(self) -> str:
        """A line safe to print, naming the network but never the key."""
        parts = []
        if self.network_name:
            parts.append(f"network {self.network_name!r}")
        if self.pan_id is not None:
            parts.append(f"PAN 0x{self.pan_id:04x}")
        if self.channel is not None:
            parts.append(f"channel {self.channel}")
        parts.append(f"{len(self.key) * 8}-bit key")
        return ", ".join(parts)


def normalise_key(raw: str) -> str:
    """Accepts hex with or without separators; returns 32 lowercase hex chars."""
    cleaned = re.sub(r"[\s:.\-]", "", raw).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not re.fullmatch(r"[0-9a-f]{32}", cleaned):
        raise ThreadKeyError(
            f"expected 32 hex characters (128 bits), got {len(cleaned)}"
        )
    return cleaned


def parse_dataset(blob: bytes) -> list[tuple[int, bytes]]:
    """Splits an operational dataset into its type/length/value records.

    Raises rather than returning a partial list: a dataset that runs off the
    end has been truncated in transit, and quietly using the records that did
    parse would install a key from a corrupted source.
    """
    records: list[tuple[int, bytes]] = []
    pos = 0
    while pos + 2 <= len(blob):
        kind, length = blob[pos], blob[pos + 1]
        value = blob[pos + 2:pos + 2 + length]
        if len(value) != length:
            raise ThreadKeyError(
                f"dataset truncated: TLV type 0x{kind:02x} wants {length} "
                f"bytes, {len(value)} present"
            )
        records.append((kind, value))
        pos += 2 + length
    if pos != len(blob):
        raise ThreadKeyError(f"dataset has {len(blob) - pos} trailing bytes")
    return records


def credentials_from_dataset(blob: bytes) -> ThreadCredentials:
    """Pulls the key and the network's identity out of a dataset."""
    key: bytes | None = None
    channel: int | None = None
    pan_id: int | None = None
    name: str | None = None

    for kind, value in parse_dataset(blob):
        if kind == TLV_NETWORK_KEY:
            key = value
        elif kind == TLV_CHANNEL and len(value) == 3:
            # Page, then a 16-bit channel, big-endian.
            channel = int.from_bytes(value[1:], "big")
        elif kind == TLV_PAN_ID and len(value) == 2:
            pan_id = int.from_bytes(value, "big")
        elif kind == TLV_NETWORK_NAME:
            name = value.decode("utf-8", "replace")

    if key is None:
        raise ThreadKeyError("dataset contains no Network Key TLV (type 0x05)")
    if len(key) != KEY_BYTES:
        raise ThreadKeyError(
            f"Network Key TLV is {len(key)} bytes, expected {KEY_BYTES}"
        )
    return ThreadCredentials(
        key=key,
        channel=channel,
        pan_id=pan_id,
        network_name=name,
        from_dataset=True,
    )


def read_credentials(path: str | os.PathLike[str]) -> ThreadCredentials:
    """Reads either a bare network key or a full operational dataset.

    Both arrive as hex. A bare key is exactly 16 bytes; anything longer is
    treated as a dataset, which is the form a border router actually hands out.
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise ThreadKeyError(f"cannot read {path}: {exc}") from exc

    # Strip comments so a saved dataset can carry a note about which network it
    # belongs to without becoming unreadable.
    stripped = "".join(
        line.split("#", 1)[0] for line in text.splitlines()
    )
    cleaned = re.sub(r"[\s:.\-]", "", stripped).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned:
        raise ThreadKeyError(f"{path} is empty")
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        raise ThreadKeyError(f"{path} is not hexadecimal")
    if len(cleaned) % 2:
        raise ThreadKeyError(
            f"{path} has an odd number of hex digits ({len(cleaned)})"
        )

    blob = bytes.fromhex(cleaned)
    if len(blob) == KEY_BYTES:
        return ThreadCredentials(key=blob)
    if len(blob) < KEY_BYTES:
        raise ThreadKeyError(
            f"{path} holds {len(blob)} bytes: too short for a key "
            f"({KEY_BYTES}) or a dataset"
        )
    return credentials_from_dataset(blob)


def wireshark_config_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("APPDATA")
        if not base:
            raise ThreadKeyError("APPDATA is not set")
        return Path(base) / "Wireshark"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "wireshark"
    return Path.home() / ".config" / "wireshark"


def read_entries(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [
        line.rstrip("\n")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def key_table_paths(root: Path | None = None) -> list[Path]:
    """Every key table the key has to go into.

    Wireshark keeps decryption keys per configuration profile, and this project
    installs one profile per radio which an 802.15.4 capture selects
    automatically.

    Profiles do NOT inherit the root table. Measured against Wireshark 4.6.8
    with a real key and real encrypted traffic: a capture resolving to 21
    6LoWPAN frames under a profile holding the key resolved to 12 -- the
    unencrypted ones alone -- under a profile with an empty key table, and to
    12 again under a profile with no key table file at all, while the root
    table held the key throughout. Wireshark's own UAT is declared
    ``from_profile = true``, which agrees.

    So writing to every profile is required, not belt-and-braces: a key
    installed only to the root would be silently unused by exactly the profiles
    this project installs.
    """
    root = root or wireshark_config_dir()
    paths = [root / "ieee802154_keys"]
    profiles = root / "profiles"
    if profiles.is_dir():
        for directory in sorted(profiles.iterdir()):
            if directory.is_dir() and directory.name.startswith("ESP32-C6"):
                paths.append(directory / "ieee802154_keys")
    return paths


def install_key(key: bytes | str, index: int = 0,
                root: Path | None = None) -> list[Path]:
    """Writes the key into every key table, returning the ones changed.

    Keys accumulate rather than replace: several networks can be decrypted in
    one capture, and clobbering someone's existing entries would be rude.
    """
    hexkey = normalise_key(key.hex() if isinstance(key, bytes) else key)
    line = f'"{hexkey}","{index}","{HASH_TYPE_THREAD}"'

    written: list[Path] = []
    for table in key_table_paths(root):
        found = read_entries(table)
        if line in found:
            continue
        found.append(line)
        table.parent.mkdir(parents=True, exist_ok=True)
        table.write_text(HEADER + "\n".join(found) + "\n", encoding="utf-8")
        written.append(table)
    return written
