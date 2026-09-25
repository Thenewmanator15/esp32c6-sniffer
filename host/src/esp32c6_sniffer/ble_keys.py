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
