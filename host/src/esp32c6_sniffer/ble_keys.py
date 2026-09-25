"""Identity resolving keys: following a BLE device that changes its address.

A phone advertises under a resolvable private address and replaces it every
few minutes. The top half of that address is 22 random bits under the marker
01 (prand); the bottom half is a hash of prand under the device's identity
resolving key (IRK). Holding the key, every address the device will ever use
can be recognised; without it, none can.

The board's controller does the recognising during a capture: it is handed
the keys, and reports and filters each resolved device under its fixed
identity address. This module is the host's side of that -- the hash, the key
file, and the checks that tell somebody their key is backwards before they
decide their device has gone quiet.

Keys are held most significant byte first, as the Core specification and
BlueZ write them. HCI wants the reverse, and encode_ble_keys() does that.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path

from esp32c6_sniffer.control import MAX_DEVICE_KEYS

#: The byte order of the base64 "Remote IRK" that macOS Keychain shows. Apple
#: does not document it and write-ups disagree, so it is measured on a real
#: key (plan Task 15). Until then the decoded bytes are taken as written, and
#: the README does not offer base64 as supported.
KEYCHAIN_BASE64_REVERSED = False

_TYPE_WORDS = {"public": 0, "random": 1}
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{32}$")
_BASE64_KEY = re.compile(r"^[A-Za-z0-9+/]{22}==$")


def _xtime(b: int) -> int:
    b <<= 1
    return (b ^ 0x11B) if b & 0x100 else b


def _make_sbox() -> bytes:
    # The multiplicative inverse in GF(2^8), then the affine transform.
    # Computed rather than tabled: 256 bytes of hex is where typos hide.
    inverse = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            x, y, product = a, b, 0
            while y:
                if y & 1:
                    product ^= x
                x = _xtime(x)
                y >>= 1
            if product == 1:
                inverse[a] = b
                break
    box = bytearray(256)
    for i in range(256):
        x = inverse[i]
        s = x
        for shift in range(1, 5):
            s ^= ((x << shift) | (x >> (8 - shift))) & 0xFF
        box[i] = s ^ 0x63
    return bytes(box)


_SBOX = _make_sbox()
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _round_keys(key: bytes) -> list[bytes]:
    words = [key[i:i + 4] for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = words[i - 1]
        if i % 4 == 0:
            t = bytes([_SBOX[t[1]] ^ _RCON[i // 4 - 1], _SBOX[t[2]],
                       _SBOX[t[3]], _SBOX[t[0]]])
        words.append(bytes(a ^ b for a, b in zip(words[i - 4], t)))
    return [b"".join(words[r * 4:r * 4 + 4]) for r in range(11)]


def aes128_encrypt(key: bytes, block: bytes) -> bytes:
    """One AES-128 block, encryption only.

    Pure Python because the standard library has no AES, and a compiled
    dependency for one function would be an install step on every platform,
    the free-threaded 3.14t build included. It runs a few hundred times per
    capture at most.
    """
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 takes a 16-byte key and a 16-byte block")
    rounds = _round_keys(key)
    s = bytearray(a ^ b for a, b in zip(block, rounds[0]))
    for r in range(1, 11):
        s = bytearray(_SBOX[b] for b in s)
        # ShiftRows. The state is column-major: row `row`, column `c` is
        # byte c*4 + row.
        s = bytearray(s[((c + row) % 4) * 4 + row]
                      for c in range(4) for row in range(4))
        if r != 10:
            mixed = bytearray(16)
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                x = [_xtime(v) for v in a]
                mixed[c * 4 + 0] = x[0] ^ x[1] ^ a[1] ^ a[2] ^ a[3]
                mixed[c * 4 + 1] = a[0] ^ x[1] ^ x[2] ^ a[2] ^ a[3]
                mixed[c * 4 + 2] = a[0] ^ a[1] ^ x[2] ^ x[3] ^ a[3]
                mixed[c * 4 + 3] = x[0] ^ a[0] ^ a[1] ^ a[2] ^ x[3]
            s = mixed
        s = bytearray(a ^ b for a, b in zip(s, rounds[r]))
    return bytes(s)


def ah(irk: bytes, prand: int) -> int:
    """The random address hash, Core Vol 3 Part H 2.2.2: the low 24 bits of
    AES(irk, 104 zero bits then prand)."""
    block = bytes(13) + prand.to_bytes(3, "big")
    return int.from_bytes(aes128_encrypt(irk, block)[-3:], "big")


def address_bytes(text: str) -> bytes:
    """"aa:bb:cc:dd:ee:ff" (or with dashes) as six bytes, most significant
    first -- the order it is written in, not the order HCI carries it."""
    parts = text.replace("-", ":").split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        raise ValueError(f"{text!r} is not a six-byte BLE address")
    try:
        return bytes(int(p, 16) for p in parts)
    except ValueError:
        raise ValueError(f"{text!r} is not hexadecimal") from None


def normalize_address(text: str) -> str:
    return ":".join(f"{b:02x}" for b in address_bytes(text))


def resolves(irk: bytes, address: str) -> bool:
    """Does this resolvable private address belong to this key?

    False for any address that is not resolvable private (top two bits 01):
    a static or non-resolvable address carries no hash to check.
    """
    raw = address_bytes(address)
    if raw[0] >> 6 != 0b01:
        return False
    prand = int.from_bytes(raw[:3], "big")
    return ah(irk, prand) == int.from_bytes(raw[3:], "big")


def make_rpa(irk: bytes, prand: int) -> str:
    """The resolvable private address a device with this key would use for
    this prand. For tests and test transmitters: a real one is never written
    into this repository."""
    if not 0 <= prand < 1 << 24 or prand >> 22 != 0b01:
        raise ValueError("prand must be 24 bits with its top two bits 01")
    raw = prand.to_bytes(3, "big") + ah(irk, prand).to_bytes(3, "big")
    return ":".join(f"{b:02x}" for b in raw)


class KeyFileError(ValueError):
    """A device key file that cannot be used.

    The message names the file and line and never contains any field from
    that line: a key pasted into the wrong column would otherwise land in
    Wireshark's error dialog, and from there in a screenshot.
    """


@dataclass(frozen=True)
class DeviceKey:
    line: int
    #: 0 public, 1 random -- the identity address's type, as HCI numbers it.
    address_type: int
    #: The identity address, lower case with colons, most significant first.
    address: str
    #: Most significant byte first. Kept out of repr so a key never reaches
    #: a log or a traceback by way of printing the object that holds it.
    irk: bytes = field(repr=False)


def _parse_key(text: str) -> bytes | None:
    digits = text.replace(":", "")
    if _HEX_KEY.match(digits):
        return bytes.fromhex(digits)
    if _BASE64_KEY.match(text):
        raw = base64.b64decode(text)
        return raw[::-1] if KEYCHAIN_BASE64_REVERSED else raw
    return None


def parse_key_file(path) -> list[DeviceKey]:
    """Reads identity resolving keys, one device per line::

        # identity address   [public|random]   key
        11:22:33:44:55:66                      <32 hex digits>
        de:ad:be:ef:00:01    random            <32 hex digits>

    The type defaults to public, which is what phones and Apple devices use
    as their identity. Raises KeyFileError naming the line.
    """
    path = Path(path)
    try:
        # utf-8-sig: Notepad writes a byte-order mark.
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as exc:
        raise KeyFileError(
            f"cannot read device key file {path}: {exc.strerror}") from None

    keys: list[DeviceKey] = []
    seen: set[str] = set()
    for number, line in enumerate(lines, 1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        where = f"{path.name} line {number}"
        fields = text.split()
        if len(fields) == 2:
            address_text, type_word, key_text = fields[0], "public", fields[1]
        elif len(fields) == 3:
            address_text, type_word, key_text = fields
        else:
            raise KeyFileError(
                f"{where}: expected '<identity address> [public|random] "
                f"<key>', found {len(fields)} fields")
        try:
            address = normalize_address(address_text)
        except ValueError:
            raise KeyFileError(
                f"{where}: the first field is not a BLE address like "
                f"aa:bb:cc:dd:ee:ff") from None
        kind = _TYPE_WORDS.get(type_word.lower())
        if kind is None:
            raise KeyFileError(
                f"{where}: the address type must be public or random")
        irk = _parse_key(key_text)
        if irk is None:
            raise KeyFileError(
                f"{where}: the key must be 32 hex digits, or 24 characters "
                f"of base64 as macOS Keychain shows it")
        if irk == bytes(16):
            raise KeyFileError(
                f"{where}: an all-zero key means 'no key' to the controller")
        if address in seen:
            raise KeyFileError(
                f"{where}: that identity already has a key on an earlier line")
        seen.add(address)
        keys.append(DeviceKey(number, kind, address, irk))

    if not keys:
        raise KeyFileError(f"{path.name} contains no device keys")
    if len(keys) > MAX_DEVICE_KEYS:
        raise KeyFileError(
            f"{path.name} holds {len(keys)} keys; one capture takes at most "
            f"{MAX_DEVICE_KEYS}, and some boards fewer")
    return keys
