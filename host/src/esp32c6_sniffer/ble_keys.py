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
import functools
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from esp32c6_sniffer.adv import AddressType, parse_hci_advertising_reports
from esp32c6_sniffer.control import (
    BLE_ADDRESS_PUBLIC,
    BLE_ADDRESS_RANDOM,
    MAX_BLE_FILTER,
    MAX_DEVICE_KEYS,
)

#: The byte order of the base64 "Remote IRK" that macOS Keychain shows. Apple
#: does not document it and write-ups disagree, so it is measured on a real
#: key (plan Task 15). Until then the decoded bytes are taken as written, and
#: the README does not offer base64 as supported.
KEYCHAIN_BASE64_REVERSED = False

# Optional: the "fast" extra. Imported here rather than where it is used so
# that a missing package costs one failed import, not one per block.
try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as _Cipher, algorithms as _algorithms, modes as _modes,
    )
except ImportError:
    _Cipher = _algorithms = _modes = None

_encryptors = threading.local()

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


def _tables() -> tuple[tuple[int, ...], ...]:
    """The four round tables: SubBytes and MixColumns for one byte, as a
    32-bit column, in each of the column's four rotations."""
    t0 = []
    for x in range(256):
        s = _SBOX[x]
        s2 = _xtime(s)
        t0.append((s2 << 24) | (s << 16) | (s << 8) | (s2 ^ s))
    ror = lambda w, n: ((w >> n) | (w << (32 - n))) & 0xFFFFFFFF  # noqa: E731
    return (tuple(t0), tuple(ror(w, 8) for w in t0),
            tuple(ror(w, 16) for w in t0), tuple(ror(w, 24) for w in t0))


_T0, _T1, _T2, _T3 = _tables()


@functools.lru_cache(maxsize=64)
def _round_keys(key: bytes) -> tuple[int, ...]:
    """The 44 words of the key schedule. Cached: a capture holds at most a
    few keys, and expanding one cost a fifth of every block."""
    w = [int.from_bytes(key[i:i + 4], "big") for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = w[i - 1]
        if i % 4 == 0:
            t = ((_SBOX[(t >> 16) & 0xFF] << 24) | (_SBOX[(t >> 8) & 0xFF] << 16)
                 | (_SBOX[t & 0xFF] << 8) | _SBOX[t >> 24])
            t ^= _RCON[i // 4 - 1] << 24
        w.append(w[i - 4] ^ t)
    return tuple(w)


def aes_backend() -> str:
    """Which AES aes128_encrypt() runs: "cryptography" or "python"."""
    return "cryptography" if _Cipher is not None else "python"


def aes128_encrypt(key: bytes, block: bytes) -> bytes:
    """One AES-128 block, encryption only.

    Through the cryptography package when it is installed -- the host's
    optional "fast" extra, which the installers add -- and this module's own
    AES when it is not, so a plugin without it still resolves keys. The same
    answers either way; measured per block, 0.21 us against 10.4.
    """
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 takes a 16-byte key and a 16-byte block")
    if _Cipher is None:
        return _aes128_python(key, block)
    # One encryptor per key, reused: ECB carries nothing from block to
    # block, and building a cipher costs fifteen times the block. Per
    # thread, because an encryptor is not safe to share.
    key = bytes(key)
    cache = _encryptors.__dict__.setdefault("by_key", {})
    encryptor = cache.get(key)
    if encryptor is None:
        encryptor = cache[key] = _Cipher(_algorithms.AES(key),
                                         _modes.ECB()).encryptor()
    return encryptor.update(bytes(block))


def _aes128_python(key: bytes, block: bytes) -> bytes:
    """AES-128 in plain Python, for an environment without cryptography.

    The standard library has no AES. Table-driven: each round is sixteen
    lookups on 32-bit columns, and the key schedule is cached. Byte at a
    time it took 91 us a block, so with eight keys every new private
    address cost 1.5 ms and about 670 a second filled a core; this takes
    about 10 us. FIPS-197 and the Core specification's ah() sample hold it
    to the standard; tests hold it to the byte-wise version it replaced.
    """
    if len(key) != 16 or len(block) != 16:
        raise ValueError("AES-128 takes a 16-byte key and a 16-byte block")
    rk = _round_keys(bytes(key))
    t0, t1, t2, t3 = _T0, _T1, _T2, _T3
    s0 = int.from_bytes(block[0:4], "big") ^ rk[0]
    s1 = int.from_bytes(block[4:8], "big") ^ rk[1]
    s2 = int.from_bytes(block[8:12], "big") ^ rk[2]
    s3 = int.from_bytes(block[12:16], "big") ^ rk[3]
    for r in range(4, 40, 4):
        s0, s1, s2, s3 = (
            t0[s0 >> 24] ^ t1[(s1 >> 16) & 0xFF] ^ t2[(s2 >> 8) & 0xFF]
            ^ t3[s3 & 0xFF] ^ rk[r],
            t0[s1 >> 24] ^ t1[(s2 >> 16) & 0xFF] ^ t2[(s3 >> 8) & 0xFF]
            ^ t3[s0 & 0xFF] ^ rk[r + 1],
            t0[s2 >> 24] ^ t1[(s3 >> 16) & 0xFF] ^ t2[(s0 >> 8) & 0xFF]
            ^ t3[s1 & 0xFF] ^ rk[r + 2],
            t0[s3 >> 24] ^ t1[(s0 >> 16) & 0xFF] ^ t2[(s1 >> 8) & 0xFF]
            ^ t3[s2 & 0xFF] ^ rk[r + 3],
        )
    # The last round has no MixColumns: SubBytes and ShiftRows only.
    sb = _SBOX
    out = (
        ((sb[s0 >> 24] << 24) | (sb[(s1 >> 16) & 0xFF] << 16)
         | (sb[(s2 >> 8) & 0xFF] << 8) | sb[s3 & 0xFF]) ^ rk[40],
        ((sb[s1 >> 24] << 24) | (sb[(s2 >> 16) & 0xFF] << 16)
         | (sb[(s3 >> 8) & 0xFF] << 8) | sb[s0 & 0xFF]) ^ rk[41],
        ((sb[s2 >> 24] << 24) | (sb[(s3 >> 16) & 0xFF] << 16)
         | (sb[(s0 >> 8) & 0xFF] << 8) | sb[s1 & 0xFF]) ^ rk[42],
        ((sb[s3 >> 24] << 24) | (sb[(s0 >> 16) & 0xFF] << 16)
         | (sb[(s1 >> 8) & 0xFF] << 8) | sb[s2 & 0xFF]) ^ rk[43],
    )
    return b"".join(w.to_bytes(4, "big") for w in out)


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
        raw = path.read_bytes()
    except OSError as exc:
        raise KeyFileError(
            f"cannot read device key file {path}: {exc.strerror}") from None
    # UTF-8, with or without the byte-order mark Notepad writes, or UTF-16
    # with its mark, which is Notepad's "Unicode". Anything else was a raw
    # UnicodeDecodeError, which reached Wireshark as a Python traceback.
    encoding = ("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
                else "utf-8-sig")
    try:
        lines = raw.decode(encoding).splitlines()
    except UnicodeDecodeError:
        raise KeyFileError(
            f"{path.name} is not UTF-8 text: save it as UTF-8") from None

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


def filter_entries(typed, keys, capacity: int = MAX_BLE_FILTER):
    """Turns addresses typed into "Only these devices" into accept-list
    entries of (type, address).

    An address named in the key file takes that identity's type: one entry.
    Any other takes two, public and random, because the type cannot be read
    from an address -- a public one may have any leading bits. Sending only
    public, as this once did, filtered every random-address device out of
    the capture entirely: measured on the C6, 0 reports against 10.
    """
    keyed = {key.address: key.address_type for key in keys}
    entries: list[tuple[int, str]] = []
    for text in typed:
        address = normalize_address(text)
        if address in keyed:
            entries.append((keyed[address], address))
        else:
            entries.append((BLE_ADDRESS_PUBLIC, address))
            entries.append((BLE_ADDRESS_RANDOM, address))
    unique = list(dict.fromkeys(entries))
    if len(unique) > capacity:
        raise ValueError(
            f"these addresses need {len(unique)} accept-list entries and the "
            f"board holds {capacity}. An address in the device key file "
            f"takes one; any other takes two, because whether it is public or "
            f"random cannot be told from the address")
    return unique


#: How long Check keys listens with no keys and no filter.
KEY_CHECK_SECONDS = 20.0

#: Distinct unresolved addresses remembered before the memory is cleared. A
#: busy room produces a few hundred an hour; this only bounds a pathological one.
_SEEN_LIMIT = 4096


def _private_addresses(hci: bytes):
    """Resolvable private addresses in one HCI packet that the board did NOT
    resolve. A resolved one arrives as an identity instead."""
    for report in parse_hci_advertising_reports(hci):
        if report.address_type == AddressType.RANDOM_RESOLVABLE:
            yield report.address


@dataclass(frozen=True)
class KeyFinding:
    key: DeviceKey
    #: True: the address resolves only with the key's bytes reversed.
    #: False: it resolves with the key as written, which the board should
    #: have done itself.
    reversed: bool
    address: str

    def message(self, file_name: str) -> str:
        where = f"Device key on line {self.key.line} of {file_name}"
        if self.reversed:
            return (f"{where} is byte-reversed: {self.address} resolves only "
                    f"with its bytes the other way round, so this device is "
                    f"not being followed. Reverse the key in the file and "
                    f"restart the capture.")
        return (f"{where} resolves {self.address}, but the board reported it "
                f"unresolved. That should not happen: the board may have "
                f"refused the key -- see the Log.")


class BackwardsKeyWatch:
    """Spots a key written the wrong way round, during an ordinary capture.

    A keyed device whose key is right arrives already resolved, so any
    resolvable private address still arriving unresolved is tested against
    each key reversed. Each address is tested once and each key reported at
    most once per capture. Costs two AES blocks per key per new address.
    """

    def __init__(self, keys):
        self._keys = list(keys)
        self._seen: set[str] = set()
        self._reported: set[int] = set()

    def observe(self, hci: bytes) -> list[KeyFinding]:
        findings: list[KeyFinding] = []
        for address in _private_addresses(hci):
            if address in self._seen:
                continue
            if len(self._seen) >= _SEEN_LIMIT:
                self._seen.clear()
            self._seen.add(address)
            for key in self._keys:
                if key.line in self._reported:
                    continue
                if resolves(key.irk[::-1], address):
                    findings.append(KeyFinding(key, True, address))
                elif resolves(key.irk, address):
                    findings.append(KeyFinding(key, False, address))
                else:
                    continue
                self._reported.add(key.line)
        return findings


@dataclass(frozen=True)
class KeyCheckResult:
    key: DeviceKey
    #: Distinct private addresses that resolved with the key as written.
    as_written: int
    #: ... that resolved only with its bytes reversed.
    reversed: int

    @property
    def verdict(self) -> str:
        if self.as_written:
            return "correct"
        if self.reversed:
            return "backwards"
        return "nothing matched"

    def message(self, file_name: str) -> str:
        head = f"{file_name} line {self.key.line} ({self.key.address})"
        if self.as_written:
            return (f"{head}: correct, {self.as_written} private "
                    f"address(es) resolved.")
        if self.reversed:
            return (f"{head}: BACKWARDS, {self.reversed} private address(es) "
                    f"resolved only with the key's bytes reversed. Reverse it "
                    f"in the file.")
        return (f"{head}: nothing matched in {KEY_CHECK_SECONDS:.0f} s. The "
                f"device was not nearby or not advertising, or the key is "
                f"wrong.")


class KeyCheck:
    """What Check keys does with the 20 s the board spends listening with no
    keys and no filter: every private address heard, tested against every
    key both ways round."""

    def __init__(self, keys):
        self._keys = list(keys)
        self._addresses: set[str] = set()

    def observe(self, hci: bytes) -> None:
        self._addresses.update(_private_addresses(hci))

    def results(self) -> list[KeyCheckResult]:
        return [KeyCheckResult(
                    key,
                    sum(resolves(key.irk, a) for a in self._addresses),
                    sum(resolves(key.irk[::-1], a) for a in self._addresses))
                for key in self._keys]


class SilenceWatch:
    """Notices a followed identity that has gone quiet.

    With the filter on, a backwards key means nothing at all arrives from
    that device -- which looks exactly like a device that is off. After
    `after_s` without a report from an identity, silent() names it once.
    """

    def __init__(self, identities, after_s: float = 30.0, *, start: float):
        self._after = after_s
        self._last = {address: start for address in identities}
        self._told: set[str] = set()

    def observe(self, hci: bytes, at: float) -> None:
        for report in parse_hci_advertising_reports(hci):
            if report.address in self._last:
                self._last[report.address] = at

    def silent(self, at: float) -> list[str]:
        quiet = [address for address, last in self._last.items()
                 if address not in self._told and at - last >= self._after]
        self._told.update(quiet)
        return quiet


def silence_message(identity: str, seconds: float) -> str:
    return (f"Nothing from {identity} for {seconds:.0f} s. If its key has "
            f"never been checked, press Check keys: a backwards key looks "
            f"exactly like this.")
