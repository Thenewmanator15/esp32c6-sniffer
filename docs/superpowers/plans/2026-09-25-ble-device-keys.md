# BLE Device Keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Follow a BLE device through its address changes. The board's controller is given each device's identity resolving key (IRK); it resolves and filters the device by identity in hardware, and the user does everything from Wireshark.

**Architecture:** The host parses a key file and sends a new wire frame (type 15, `SN_FRAME_BLE_KEYS`). Each firmware loads it into the controller's resolving list at scan start, just before the accept list. The host also:
- fixes the filter's address-type bug;
- always sends both lists;
- can swap them out mid-capture for a 20 s "Check keys" listen;
- watches unresolved private addresses for a key written backwards.

The extcap wires all of this into Wireshark: a file option, a toolbar button, the log, pop-ups and packet comments.

**Tech Stack:** Python 3.12+ (pure standard library, including a pure-Python AES-128 block), ESP-IDF v6.1 (ESP32-C6, VHCI raw HCI), NCS v3.4.0 / Zephyr raw HCI (nRF54L15), and the pcapng/extcap protocol.

**Spec:** `docs/superpowers/specs/2026-09-24-ble-device-keys-design.md`

**Deviations from the spec, decided while planning (tell the user at handoff):**
1. **No golden vector for frame 15.** `golden.json` holds frames the boards *emit* in their conformance burst. A host-to-board frame there would force both conformance builds to send a frame they never send (`BLE_FILTER` has no vector either). Instead, a host test pins frame 15's exact payload bytes and its type number.
2. **`ble_keys_firmware` is dropped.** `CaptureSession.open()` already refuses any firmware version other than `EXPECTED_FIRMWARE_VERSIONS[board]` exactly. Bumping that is the whole gate.
3. **The nRF firmware must learn to check HCI command status (Task 10).**
   - Today its `send_command()` sends a command, sleeps 20 ms and returns `bt_send()`'s result. So a command the controller *refuses* is never noticed.
   - The spec's "a refused command fails the scan start" is therefore false on the nRF until this is fixed.
4. **The host always sends the keys frame and the filter frame at BLE start, empty when unused.**
   - The nRF54L15 does not reset when its port opens, so its RAM keeps the last capture's filter. A capture with no filter after one with a filter was filtered anyway. This is found by reading the code; Task 10 Step 2 measures it before the fix, and Task 13 after.
5. **The extcap's toolbar wiring is tested structurally, not through a live control pipe.**
   - `do_capture()` cannot run in-process without a board and pipes. The repo's existing approach for its wiring is AST tests (`test_shutdown.py`).
   - The behaviour itself is unit-tested in the library, and the real button press is the user's GUI check (Task 15).

## Global Constraints

- **Python:** floor 3.12. CI runs 3.12, 3.14 and 3.14t on Windows and Ubuntu. Pure standard library only; no new dependencies.
- **Wire format:** add frame type 15 only. No existing frame changes.
- **`shared/`** may depend on nothing but `<stddef.h>`, `<stdint.h>` and `<string.h>`.
- **Keys are secret.**
  - Firmware logs the count only, never key bytes.
  - Host error messages never contain any field of a key-file line.
  - Keys never go into the capture file and never into either repo.
  - Test data uses only the Core spec sample key `ec0234a357c8ad05341010a60a397d9b`.
- **MAC-like `xx:xx:xx:xx:xx:xx` strings in tracked files** may only be `00:00:00:00:00:00`, `01:02:03:04:05:06`, `11:22:33:44:55:66`, `aa:bb:cc:dd:ee:ff`, `de:ad:be:ef:00:01` or `ff:ff:ff:ff:ff:ff`. The guard is `host/tests/test_no_private_data.py`. Build private addresses at runtime with `make_rpa()`; never write one literally.
  - Identity used throughout: `de:ad:be:ef:00:01`, random (its top two bits are 11, so it is a valid random static address).
  - Public example: `11:22:33:44:55:66`.
- **The sniffers stay passive.** Test transmitters are throwaway builds outside both repos (`G:\dev\scratch\nrf\rpaadv`, and the session scratchpad's `c6vhciadv`).
- **Capacities:**
  - device keys: ESP32-C6 5 (Kconfig maximum), nRF54L15 8;
  - accept list: 8 on both;
  - frame 15: at most 8 entries of 23 bytes.
- **Firmware versions** take the next free number when built. On 2026-09-25 that is C6 6 → 7 and nRF 4 → 5. Re-check `EXPECTED_FIRMWARE_VERSIONS` in `host/src/esp32c6_sniffer/capture.py` and `SN_FIRMWARE_VERSION` in both firmwares at the start of Tasks 9 and 11; if either moved, take the next free number.
- **Commits** end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Do not push. Stage only this work's files.
- **The other Claude session** ("Bluetooth exploration status") also works in both repos and on both boards. Message it before using COM3/COM4 or editing nRF `src/radio_ble.c`, and never touch its commits or branches.
- **Builds and flashing:**
  - ESP-IDF builds run from pwsh, never Git Bash (MSYSTEM breaks `export.ps1`).
  - The nRF is flashed with `--verify` (the local openocd RRAM patch).
- **Shell quoting:** write Python and C through the Write/Edit tools, not heredocs. Backslashes have been mangled by the shell layers here before.

## Review Focus

1. **A key file saved by Notepad (UTF-8 with BOM, CRLF line endings)** must parse like any other. The test goes in Task 2.
2. **The same device typed twice, or in different case or with dashes, in "Only these devices"** must use one set of accept-list entries, not two. The test goes in Task 4.
3. **An identity written differently in the key file and the filter** (`DE-AD-BE-EF-00-01` against `de:ad:be:ef:00:01`) must still count as keyed and take one slot. The test goes in Task 4.
4. **Pressing Check keys twice quickly** must start one check. The second request is refused (`request_key_check` returns False) and the log says a check is running. The test goes in Task 7.
5. **Wireshark stopping the capture while a check is running** must end `records()` cleanly, without raising or calling `on_done`. The next capture still starts clean because the lists are always sent. The test goes in Task 7.

---

## Workspace and file map

The work happens in git worktrees, because the other session commits to `main` in the same checkouts.
- **esp32c6-sniffer:** `G:\dev\projects\esp32c6-sniffer-keys`, branch `ble-device-keys`. Its `shared` submodule gets branch `ble-keys-frame`.
- **nrf54l15-sniffer:** `G:\dev\projects\nrf54l15-sniffer-keys`, branch `ble-device-keys`.

Paths below are relative to the esp32c6-sniffer worktree unless they start with `nrf:`.

| File | Change | Responsibility |
|---|---|---|
| `host/src/esp32c6_sniffer/ble_keys.py` | create | AES-128, `ah`, `resolves`, `make_rpa`; key file parsing; accept-list entries; backwards-key watch; Check keys tally; silence watch; user-facing messages |
| `host/src/esp32c6_sniffer/control.py` | modify | `MAX_DEVICE_KEYS`, `encode_ble_keys()` |
| `host/src/esp32c6_sniffer/framing.py` | modify | `FrameType.BLE_KEYS = 15` |
| `host/src/esp32c6_sniffer/boards.py` | modify | `"ble_keys"` capacity per board |
| `host/src/esp32c6_sniffer/adv.py` | modify | identity address types, `parse_hci_advertising_reports()` |
| `host/src/esp32c6_sniffer/ble.py` | modify | `hci_of_record()` |
| `host/src/esp32c6_sniffer/capture.py` | modify | `ble_keys=`; always send both lists; `request_key_check()`; `records()` split into `_records_from()`; expected firmware versions |
| `extcap/esp32c6-sniffer.py` | modify | `--ble-keys` option, filter tooltip and typing, Check keys control, watches, messages |
| `shared/frame.h` | modify (submodule) | `SN_FRAME_BLE_KEYS = 15` |
| `firmware/main/control.[ch]` | modify | dispatch frame 15 |
| `firmware/main/radio_ble.[ch]` | modify | key storage, `apply_keys()`, clear on stop |
| `firmware/main/main.c` | modify | handler, version 7 |
| `firmware/sdkconfig.defaults` | modify | `CONFIG_BT_LE_LL_RESOLV_LIST_SIZE=5` |
| `nrf:src/radio_ble.[ch]` | modify | command status checking; key storage, `apply_keys()`, clear on stop |
| `nrf:src/control.c` | modify | dispatch frame 15 |
| `nrf:src/main.c` | modify | version 5 |
| `nrf:prj.conf` | modify | privacy and resolving list stated explicitly |
| `README.md`, `nrf:README.md` | modify | docs |
| `host/tests/test_ble_keys.py` | create | crypto, parser, entries, watches |
| `host/tests/test_ble_keys_capture.py` | create | session behaviour with a fake board |
| `host/tests/test_ble_filter.py`, `test_adv.py`, `test_extcap.py`, `test_board_table.py` | modify | as each task says |

**Running host tests in the worktree** (Git Bash). The venv lives in the main checkout; `PYTHONPATH` makes the worktree's source win:

```bash
cd /g/dev/projects/esp32c6-sniffer-keys/host
PYTHONPATH=src /g/dev/projects/esp32c6-sniffer/host/.venv/Scripts/python.exe -m pytest -q tests/test_ble_keys.py
```

In later steps, `PYTEST` stands for `PYTHONPATH=src /g/dev/projects/esp32c6-sniffer/host/.venv/Scripts/python.exe -m pytest`, run from the worktree's `host/`.

---

### Task 0: Workspace and coordination

**Files:** none in the repos. Creates two worktrees and one scratch helper.

**Interfaces:**
- Produces: the two worktrees above, and `<scratchpad>/nrf_build.ps1 -Ncs <sdk root> -App <dir> -Build <dir> [-Mode 2]`.

- [ ] **Step 1: Create the worktrees and initialise their submodules**

```bash
git -C /g/dev/projects/esp32c6-sniffer pull --ff-only
git -C /g/dev/projects/esp32c6-sniffer worktree add /g/dev/projects/esp32c6-sniffer-keys -b ble-device-keys
git -C /g/dev/projects/esp32c6-sniffer-keys submodule update --init
git -C /g/dev/projects/nrf54l15-sniffer pull --ff-only
git -C /g/dev/projects/nrf54l15-sniffer worktree add /g/dev/projects/nrf54l15-sniffer-keys -b ble-device-keys
git -C /g/dev/projects/nrf54l15-sniffer-keys submodule update --init
```

Expected: both worktrees exist, and `git -C <worktree> submodule status` shows `shared` checked out.

- [ ] **Step 2: Run the host suite in the new worktree as a baseline**

Run: `cd /g/dev/projects/esp32c6-sniffer-keys/host && $PYTEST -q -x`
Expected: all pass (about 600, one skipped). Stop if not: the baseline must be green.

- [ ] **Step 3: Write the nRF build helper (throwaway, in the scratchpad)**

Create `<scratchpad>/nrf_build.ps1`:

```powershell
# Builds an nRF54L15 sniffer. Throwaway helper for this session.
# -Ncs is the nRF Connect SDK root: the folder holding toolchains\ and v3.4.0\.
param([Parameter(Mandatory)][string]$Ncs, [Parameter(Mandatory)][string]$App,
      [Parameter(Mandatory)][string]$Build, [int]$Mode = 2)
$tc = Join-Path $Ncs "toolchains\dcbdc366a1"
$env:PATH = (@(".","mingw64/bin","bin","opt/bin","opt/bin/Scripts","opt/nanopb/generator-bin","nrfutil/bin","opt/zephyr-sdk/gnu/arm-zephyr-eabi/bin","opt/zephyr-sdk/gnu/riscv64-zephyr-elf/bin") | ForEach-Object { Join-Path $tc $_ }) -join ";" | ForEach-Object { "$_;$env:PATH" }
$env:PYTHONPATH = (@("opt/bin","opt/bin/Lib","opt/bin/Lib/site-packages") | ForEach-Object { Join-Path $tc $_ }) -join ";"
$env:NRFUTIL_HOME = Join-Path $tc "nrfutil/home"
$env:ZEPHYR_TOOLCHAIN_VARIANT = "zephyr/gnu"
$env:ZEPHYR_SDK_INSTALL_DIR = Join-Path $tc "opt/zephyr-sdk"
$env:ZEPHYR_BASE = Join-Path $Ncs "v3.4.0\zephyr"
Set-Location (Join-Path $Ncs "v3.4.0")
west build -b xiao_nrf54l15/nrf54l15/cpuapp -s $App -d $Build -- "-DSN_MODE=$Mode" 2>&1 | Select-String -Pattern "error|warning: |Memory region|FLASH:|RAM:" | Select-Object -Last 15
"exit $LASTEXITCODE"
```

On this machine the SDK root is G:\dev\tools\ncs. Flash with the existing `<scratchpad>/nrf_flash_verify.ps1 -Build <dir>`.

- [ ] **Step 4: Tell the other session**

SendMessage to "Bluetooth exploration status" with this text:

> Starting BLE device keys implementation in worktrees esp32c6-sniffer-keys and nrf54l15-sniffer-keys (branch ble-device-keys). I will edit nrf src/radio_ble.c, src/control.c, src/main.c and prj.conf there, plus frame type 15 in shared. Nothing touches main until the end, and I'll message before touching COM3/COM4.

---

### Task 1: IRK crypto (AES-128, ah, resolves, make_rpa)

**Files:**
- Create: `host/src/esp32c6_sniffer/ble_keys.py`
- Create: `host/tests/test_ble_keys.py`

**Interfaces:**
- Produces:
  - `aes128_encrypt(key: bytes, block: bytes) -> bytes`
  - `ah(irk: bytes, prand: int) -> int`
  - `address_bytes(text: str) -> bytes` (most significant first; raises `ValueError`)
  - `normalize_address(text: str) -> str` (lower case, colons)
  - `resolves(irk: bytes, address: str) -> bool`
  - `make_rpa(irk: bytes, prand: int) -> str`
  - Throughout, `irk` is 16 bytes **most significant first**, as the Core spec writes it.

- [ ] **Step 1: Write the failing tests**

`host/tests/test_ble_keys.py`:

```python
"""Identity resolving keys: the hash, the key file, and the checks built on
them. Only the Core specification's own sample key appears here; a real key
in a repository would let anyone follow the device it belongs to."""

import pytest

from esp32c6_sniffer.ble_keys import (
    address_bytes,
    aes128_encrypt,
    ah,
    make_rpa,
    normalize_address,
    resolves,
)

#: Core specification v5.4, Vol 3 Part H, 2.2 sample data, written most
#: significant byte first as the specification writes it.
IRK = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
IDENTITY = "de:ad:be:ef:00:01"


def test_aes_matches_fips_197_appendix_c1():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert aes128_encrypt(key, plain).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_aes_refuses_the_wrong_sizes():
    with pytest.raises(ValueError):
        aes128_encrypt(bytes(15), bytes(16))
    with pytest.raises(ValueError):
        aes128_encrypt(bytes(16), bytes(17))


def test_ah_matches_the_core_specification_sample():
    assert ah(IRK, 0x708194) == 0x0DFBAA


def test_an_address_made_from_a_key_resolves_with_it():
    for prand in (0x400001, 0x5ABCDE, 0x7FFFFF):
        assert resolves(IRK, make_rpa(IRK, prand))


def test_it_does_not_resolve_with_the_key_reversed():
    assert not resolves(IRK[::-1], make_rpa(IRK, 0x400001))


def test_only_a_resolvable_private_address_can_resolve():
    """Top two bits 11 is static, 00 non-resolvable: neither carries a hash."""
    assert not resolves(IRK, IDENTITY)
    assert not resolves(IRK, "11:22:33:44:55:66")


def test_make_rpa_wants_a_resolvable_prand():
    with pytest.raises(ValueError):
        make_rpa(IRK, 0xC00001)          # top bits 11
    with pytest.raises(ValueError):
        make_rpa(IRK, 1 << 24)


def test_addresses_accept_colons_dashes_and_either_case():
    assert address_bytes("DE-AD-BE-EF-00-01") == bytes.fromhex("deadbeef0001")
    assert normalize_address("DE-AD-BE-EF-00-01") == IDENTITY


@pytest.mark.parametrize("bad", ["", "de:ad:be:ef:00", "de:ad:be:ef:00:01:02",
                                 "zz:ad:be:ef:00:01", "deadbeef0001"])
def test_a_malformed_address_is_refused(bad):
    with pytest.raises(ValueError):
        address_bytes(bad)
```

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'esp32c6_sniffer.ble_keys'`.

- [ ] **Step 3: Implement**

`host/src/esp32c6_sniffer/ble_keys.py`. This code was checked against both vectors while the plan was written, at 91 µs per block on 3.14:

```python
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
```

- [ ] **Step 4: Run the tests and check that they pass**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: 10 passed.

- [ ] **Step 5: Commit**

```bash
cd /g/dev/projects/esp32c6-sniffer-keys
git add host/src/esp32c6_sniffer/ble_keys.py host/tests/test_ble_keys.py
git commit -m "feat: the BLE random address hash, in pure Python

AES-128 and ah() from the Core specification, checked against FIPS-197
and the specification's own sample, so the host can tell which private
addresses belong to a key.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Key file parser

**Files:**
- Modify: `host/src/esp32c6_sniffer/ble_keys.py`
- Modify: `host/tests/test_ble_keys.py`

**Interfaces:**
- Consumes: `address_bytes`, `normalize_address` (Task 1).
- Produces:
  - `KeyFileError(ValueError)`
  - `DeviceKey(line: int, address_type: int, address: str, irk: bytes)` — frozen; `irk` is hidden from `repr`; `address` is normalised.
  - `parse_key_file(path) -> list[DeviceKey]`
  - `KEYCHAIN_BASE64_REVERSED: bool = False`
  - `MAX_DEVICE_KEYS` is imported from `control.py` (added in Task 3). **Until Task 3, define `MAX_DEVICE_KEYS = 8` in `ble_keys.py`; Task 3 moves it.**

- [ ] **Step 1: Write the failing tests** (append to `host/tests/test_ble_keys.py`)

```python
import base64

from esp32c6_sniffer.ble_keys import (
    KEYCHAIN_BASE64_REVERSED,
    DeviceKey,
    KeyFileError,
    parse_key_file,
)

IRK_HEX = IRK.hex()
IRK_B64 = base64.b64encode(IRK).decode()


def keyfile(tmp_path, text, name="keys.txt", **write):
    path = tmp_path / name
    path.write_text(text, encoding=write.pop("encoding", "utf-8"), **write)
    return path


def test_a_public_identity_with_a_hex_key(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"11:22:33:44:55:66 {IRK_HEX}\n"))
    assert keys == [DeviceKey(1, 0, "11:22:33:44:55:66", IRK)]


def test_a_random_identity_with_a_type_word(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {IRK_HEX}\n"))
    assert (keys[0].address_type, keys[0].address) == (1, IDENTITY)


def test_the_type_word_is_case_insensitive(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} RANDOM {IRK_HEX}\n"))
    assert keys[0].address_type == 1


def test_colons_in_a_hex_key_are_allowed(tmp_path):
    spaced = ":".join(IRK_HEX[i:i + 2] for i in range(0, 32, 2))
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {spaced}\n"))
    assert keys[0].irk == IRK


def test_a_base64_key_is_read_in_the_measured_order(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {IRK_B64}\n"))
    assert keys[0].irk == (IRK[::-1] if KEYCHAIN_BASE64_REVERSED else IRK)


def test_comments_blank_lines_and_line_numbers(tmp_path):
    text = f"# my phone\n\n{IDENTITY} random {IRK_HEX}  # after\n"
    assert parse_key_file(keyfile(tmp_path, text))[0].line == 3


def test_a_notepad_file_with_bom_and_crlf_parses(tmp_path):
    """Review focus 1: Notepad writes a byte-order mark and CRLF."""
    path = tmp_path / "keys.txt"
    path.write_bytes(("# phone\r\n" + f"{IDENTITY} random {IRK_HEX}\r\n")
                     .encode("utf-8-sig"))
    assert parse_key_file(path)[0].address == IDENTITY


def test_the_identity_is_normalised(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"DE-AD-BE-EF-00-01 random {IRK_HEX}\n"))
    assert keys[0].address == IDENTITY


def test_the_key_is_not_in_the_repr(tmp_path):
    keys = parse_key_file(keyfile(tmp_path, f"{IDENTITY} random {IRK_HEX}\n"))
    assert IRK_HEX not in repr(keys[0]) and "ec02" not in repr(keys[0])


@pytest.mark.parametrize("line, fragment", [
    (f"{IRK_HEX} {IDENTITY}", "not a BLE address"),     # fields swapped
    (f"{IDENTITY} sideways {IRK_HEX}", "public or random"),
    (f"{IDENTITY} random {IRK_HEX[:-2]}", "32 hex digits"),
    (f"{IDENTITY} random {IRK_HEX} extra", "fields"),
    (f"{IDENTITY} {IRK_HEX} random", "public or random"),  # type after key
    (f"{IDENTITY} random {'0' * 32}", "all-zero"),
    (IRK_HEX, "fields"),
])
def test_a_bad_line_is_refused_by_line_without_echoing_it(tmp_path, line, fragment):
    with pytest.raises(KeyFileError) as caught:
        parse_key_file(keyfile(tmp_path, f"# first\n{line}\n"))
    message = str(caught.value)
    assert "line 2" in message and fragment in message
    for token in line.split():
        if token.lower() in ("public", "random"):
            continue            # the format description names these words
        assert token not in message, "an error message must never echo a field"


def test_a_repeated_identity_is_refused(tmp_path):
    text = f"{IDENTITY} random {IRK_HEX}\nDE:AD:BE:EF:00:01 public {IRK_B64}\n"
    with pytest.raises(KeyFileError, match="line 2.*earlier"):
        parse_key_file(keyfile(tmp_path, text))


def test_more_than_eight_keys_is_refused(tmp_path):
    lines = "".join(f"11:22:33:44:55:{n:02x} {IRK_HEX}\n" for n in range(9))
    with pytest.raises(KeyFileError, match="9 keys"):
        parse_key_file(keyfile(tmp_path, lines))


def test_an_empty_file_is_refused(tmp_path):
    with pytest.raises(KeyFileError, match="no device keys"):
        parse_key_file(keyfile(tmp_path, "# nothing yet\n"))


def test_a_missing_file_is_refused_by_name(tmp_path):
    with pytest.raises(KeyFileError, match="missing.txt"):
        parse_key_file(tmp_path / "missing.txt")
```

The `11:22:33:44:55:{n:02x}` f-string is not a literal MAC in the file, so the private-data guard does not see it.

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: ImportError for `DeviceKey`.

- [ ] **Step 3: Implement** (append to `ble_keys.py`, and add the imports at the top)

```python
import base64
import re
from dataclasses import dataclass, field
from pathlib import Path

#: The byte order of the base64 "Remote IRK" that macOS Keychain shows. Apple
#: does not document it and write-ups disagree, so it is measured on a real
#: key (plan Task 15). Until then the decoded bytes are taken as written, and
#: the README does not offer base64 as supported.
KEYCHAIN_BASE64_REVERSED = False

#: What one SN_FRAME_BLE_KEYS frame carries. Boards hold fewer: see
#: boards.py "ble_keys".
MAX_DEVICE_KEYS = 8

_TYPE_WORDS = {"public": 0, "random": 1}
_HEX_KEY = re.compile(r"^[0-9a-fA-F]{32}$")
_BASE64_KEY = re.compile(r"^[A-Za-z0-9+/]{22}==$")


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
```

- [ ] **Step 4: Run the tests and check that they pass**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: all pass. If the "does not echo" test fails on the swapped-fields case, check that the address error message contains no field.

- [ ] **Step 5: Run the private-data guard and commit**

Run: `$PYTEST tests/test_no_private_data.py tests/test_no_stray_control_characters.py -q`
Expected: pass.

```bash
git add host/src/esp32c6_sniffer/ble_keys.py host/tests/test_ble_keys.py
git commit -m "feat: read device keys from a file, naming bad lines without echoing them

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Frame type 15 on the wire

**Files:**
- Modify: `host/src/esp32c6_sniffer/framing.py` (FrameType)
- Modify: `host/src/esp32c6_sniffer/control.py` (after `encode_ble_filter`, about line 276)
- Modify: `host/src/esp32c6_sniffer/ble_keys.py` (import `MAX_DEVICE_KEYS` instead of defining it)
- Modify: `host/src/esp32c6_sniffer/boards.py` (both entries)
- Modify: `shared/frame.h` (submodule, branch `ble-keys-frame`)
- Test: `host/tests/test_ble_keys.py`, `host/tests/test_board_table.py`

**Interfaces:**
- Produces:
  - `FrameType.BLE_KEYS == 15`
  - `control.MAX_DEVICE_KEYS = 8`
  - `control.encode_ble_keys(keys) -> bytes` (each key has `.address_type`, `.address`, `.irk`)
  - `BOARDS[...]["ble_keys"]`: 5 for esp32c6, 8 for nrf54l15
  - C: `SN_FRAME_BLE_KEYS = 15`

- [ ] **Step 1: Write the failing tests** (append to `test_ble_keys.py`)

```python
from esp32c6_sniffer.boards import board_by_id
from esp32c6_sniffer.control import MAX_DEVICE_KEYS, encode_ble_keys
from esp32c6_sniffer.framing import FrameType, decode_frame

KEY = DeviceKey(1, 1, IDENTITY, IRK)


def test_the_keys_frame_is_type_15():
    """Pinned: shared/frame.h says 15 too, and both firmwares dispatch on it."""
    assert FrameType.BLE_KEYS == 15
    assert decode_frame(encode_ble_keys([KEY])).ftype is FrameType.BLE_KEYS


def test_one_key_is_23_bytes_least_significant_first():
    payload = decode_frame(encode_ble_keys([KEY])).payload
    assert payload.hex() == (
        "01"                                   # random
        "0100efbeadde"                         # de:ad:be:ef:00:01, LSB first
        "9b7d390aa610103405adc857a33402ec")    # the sample IRK, reversed


def test_an_empty_list_clears_the_keys():
    assert decode_frame(encode_ble_keys([])).payload == b""


def test_more_than_a_frame_holds_is_refused():
    keys = [DeviceKey(n, 0, f"11:22:33:44:55:{n:02x}", IRK)
            for n in range(MAX_DEVICE_KEYS + 1)]
    with pytest.raises(ValueError, match="at most 8"):
        encode_ble_keys(keys)


def test_each_board_says_how_many_keys_it_holds():
    """The C6's resolving list tops out at 5 in its Kconfig; the nRF's is 8."""
    assert board_by_id("esp32c6")["ble_keys"] == 5
    assert board_by_id("nrf54l15")["ble_keys"] == 8
```

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: ImportError for `MAX_DEVICE_KEYS` from `control`.

- [ ] **Step 3: Implement**

In `framing.py`, after `BLE_BATCH = 14` inside `FrameType`:

```python
    #: Host to board: identity resolving keys, so the controller reports and
    #: filters a device that changes its address under its identity address.
    #: N x 23 bytes: identity type, identity address, key -- the last two
    #: least significant byte first. Empty clears. See ble_keys.
    BLE_KEYS = 15
```

In `control.py`, after `encode_ble_filter`:

```python
#: Device keys one SN_FRAME_BLE_KEYS frame carries. Each board holds fewer or
#: as many: boards.py "ble_keys".
MAX_DEVICE_KEYS = 8


def encode_ble_keys(keys) -> bytes:
    """Frames identity resolving keys for the board's resolving list.

    Each key is anything with address_type (0 public, 1 random), address
    ("aa:bb:cc:dd:ee:ff") and irk (16 bytes, most significant first) --
    ble_keys.DeviceKey in practice. On the wire each is 23 bytes: the type,
    then the address and the key least significant byte first, as HCI
    carries both. An empty list clears the keys.

    The board keeps them in RAM for one capture and never logs them.
    """
    if len(keys) > MAX_DEVICE_KEYS:
        raise ValueError(
            f"{len(keys)} device keys; a frame carries at most "
            f"{MAX_DEVICE_KEYS}")
    payload = bytearray()
    for key in keys:
        if key.address_type not in (BLE_ADDRESS_PUBLIC, BLE_ADDRESS_RANDOM):
            raise ValueError(f"address type {key.address_type} is not 0 or 1")
        if len(key.irk) != 16:
            raise ValueError("a device key is 16 bytes")
        payload.append(key.address_type)
        payload += bytes.fromhex(key.address.replace(":", ""))[::-1]
        payload += key.irk[::-1]
    return encode_frame(FrameType.BLE_KEYS, 0, bytes(payload))
```

In `ble_keys.py`, delete `MAX_DEVICE_KEYS = 8` and its comment, and add:

```python
from esp32c6_sniffer.control import MAX_DEVICE_KEYS
```

In `boards.py`, add to the esp32c6 entry after `"ble_periodic": True,`:

```python
        # Identity resolving keys the controller's resolving list holds.
        # CONFIG_BT_LE_LL_RESOLV_LIST_SIZE, whose Kconfig range is 1 to 5.
        "ble_keys": 5,
```

and to the nrf54l15 entry after `"ble_periodic": True,`:

```python
        # CONFIG_BT_CTLR_RL_SIZE in prj.conf.
        "ble_keys": 8,
```

In `shared/frame.h`, after `SN_FRAME_BLE_BATCH = 14,`:

```c

    /* Host to board: identity resolving keys, so the controller reports and
     * filters a device that changes its address under its fixed identity
     * address instead. N x 23 bytes -- identity address type (0 public,
     * 1 random), the identity address, the 16-byte key, both least
     * significant byte first as HCI carries them. An empty payload clears
     * the keys. Kept in RAM for one capture and never logged.
     * Authoritative layout: encode_ble_keys in the host's control.py. */
    SN_FRAME_BLE_KEYS = 15,
```

- [ ] **Step 4: Run the tests and check that they pass**

Run: `$PYTEST tests/test_ble_keys.py tests/test_board_table.py tests/test_framing.py -q`
Expected: all pass. If `test_board_table.py` checks for an exact key set per board, add `"ble_keys"` to its expected set.

- [ ] **Step 5: Commit the submodule first, then the superproject**

```bash
cd /g/dev/projects/esp32c6-sniffer-keys/shared
git checkout -b ble-keys-frame
git add frame.h
git commit -m "a frame type for identity resolving keys

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
cd ..
git add shared host/src/esp32c6_sniffer/framing.py host/src/esp32c6_sniffer/control.py \
        host/src/esp32c6_sniffer/ble_keys.py host/src/esp32c6_sniffer/boards.py \
        host/tests/test_ble_keys.py host/tests/test_board_table.py
git commit -m "feat: frame type 15 carries device keys to the board

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Accept-list entries, and a session that always sends both lists

**Files:**
- Modify: `host/src/esp32c6_sniffer/ble_keys.py`
- Modify: `host/src/esp32c6_sniffer/capture.py` (`__init__` about line 322; the `_configure` BLE block about lines 560-567)
- Create: `host/tests/test_ble_keys_capture.py`
- Modify: `host/tests/test_ble_keys.py`

**Interfaces:**
- Consumes: `DeviceKey`, `normalize_address`, `encode_ble_keys`, `encode_ble_filter`, `board_by_id`.
- Produces:
  - `ble_keys.filter_entries(typed: list[str], keys: list[DeviceKey], capacity: int = MAX_BLE_FILTER) -> list[tuple[int, str]]`
  - `ble.hci_of_record(record: bytes) -> bytes`
  - `CaptureSession(..., ble_keys: list[DeviceKey] | None = None)`
  - `CaptureSession._send_ble_lists(keys, entries) -> None`

- [ ] **Step 1: Write the failing entry tests** (append to `test_ble_keys.py`)

```python
from esp32c6_sniffer.ble_keys import filter_entries


def test_a_keyed_identity_takes_one_entry_of_its_own_type():
    assert filter_entries([IDENTITY], [KEY]) == [(1, IDENTITY)]


def test_a_plain_address_takes_both_types():
    """The measured bug: typed addresses went out as public only, and a
    random-address device was filtered out entirely (0 reports against 10)."""
    assert filter_entries(["11:22:33:44:55:66"], []) == [
        (0, "11:22:33:44:55:66"), (1, "11:22:33:44:55:66")]


def test_the_same_device_typed_twice_takes_its_entries_once():
    """Review focus 2."""
    typed = ["11:22:33:44:55:66", "11-22-33-44-55-66", "11:22:33:44:55:66".upper()]
    assert len(filter_entries(typed, [])) == 2


def test_an_identity_written_differently_still_counts_as_keyed():
    """Review focus 3."""
    assert filter_entries(["DE-AD-BE-EF-00-01"], [KEY]) == [(1, IDENTITY)]


def test_four_plain_addresses_fit_and_five_do_not():
    four = [f"11:22:33:44:55:{n:02x}" for n in range(4)]
    assert len(filter_entries(four, [])) == 8
    with pytest.raises(ValueError, match="holds 8"):
        filter_entries(four + ["de:ad:be:ef:00:01"], [])


def test_eight_keyed_identities_fit():
    keys = [DeviceKey(n, 1, f"de:ad:be:ef:00:{n:02x}", IRK) for n in range(8)]
    assert len(filter_entries([k.address for k in keys], keys)) == 8
```

- [ ] **Step 2: Write the failing session tests**

Create `host/tests/test_ble_keys_capture.py`:

```python
"""A BLE capture carrying device keys, against a board faked at the frame
level. The board is the one that answers; these check what the host sends it
and in which order, and what the host does with what comes back."""

import struct

import pytest

from esp32c6_sniffer import capture
from esp32c6_sniffer.ble import hci_of_record
from esp32c6_sniffer.ble_keys import DeviceKey, make_rpa
from esp32c6_sniffer.capture import CaptureSession, EXPECTED_FIRMWARE_VERSIONS
from esp32c6_sniffer.control import Command, Radio
from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import StreamParser

IRK = bytes.fromhex("ec0234a357c8ad05341010a60a397d9b")
IDENTITY = "de:ad:be:ef:00:01"
KEY = DeviceKey(1, 1, IDENTITY, IRK)


def ext_report(address: str, address_type: int = 1) -> bytes:
    """One LE Extended Advertising Report, as the controller sends it."""
    raw = bytes.fromhex(address.replace(":", ""))[::-1]
    body = bytearray([1, 0x10, 0x00, address_type]) + raw
    body += bytes([0x01, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00, 0x00]) + bytes(6)
    body += bytes([0])
    return bytes([0x04, 0x3E, len(body) + 1, 0x0D]) + bytes(body)


class KeyedBoard:
    """Answers commands as the firmware does and records every frame written.

    before[cmd] and after[cmd] are queues of packet lists: each time that
    command arrives, the next list is sent ahead of its reply or behind it.
    That is how a test puts a packet on either side of a STOP."""

    def __init__(self, board: str):
        self.version = EXPECTED_FIRMWARE_VERSIONS[board]
        self.rx = bytearray()
        self.seq = 0
        self.written: list[tuple[FrameType, int | None, bytes]] = []
        self.before: dict[int, list[list[bytes]]] = {}
        self.after: dict[int, list[list[bytes]]] = {}
        self.reads = 0

    def set_buffer_size(self, **_):
        pass

    def reset_input_buffer(self):
        self.rx.clear()

    @property
    def in_waiting(self):
        return len(self.rx)

    def flush(self):
        pass

    def close(self):
        pass

    def read(self, n=1):
        self.reads += 1
        if self.reads > 20000:
            raise AssertionError("records() never produced what the test waited for")
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    def packet(self, hci: bytes) -> None:
        payload = struct.pack("<QHBB", 1000 * (self.seq + 1), len(hci), 0, 0) + hci
        self.rx += encode_frame(FrameType.PACKET, self.seq, payload)
        self.seq += 1

    def _emit(self, queues, command):
        queue = queues.get(command)
        if queue:
            for hci in queue.pop(0):
                self.packet(hci)

    def write(self, data):
        for frame in StreamParser().feed(bytes(data)):
            if frame.ftype is not FrameType.CONTROL_CMD:
                self.written.append((frame.ftype, None, frame.payload))
                continue
            command, value = struct.unpack_from("<BI", frame.payload)
            self.written.append((frame.ftype, command, frame.payload))
            self._emit(self.before, command)
            if command == Command.GET_INFO:
                value = self.version
            self.rx += encode_frame(FrameType.CONTROL_REPLY, self.seq,
                                    struct.pack("<BBI", command, 0, value))
            self.seq += 1
            self._emit(self.after, command)
        return len(data)

    def sequence(self):
        """What was sent, as short names, commands by name."""
        return [Command(c).name if c is not None else t.name
                for t, c, _ in self.written]


def open_session(monkeypatch, board, keys=None, entries=None, name="nrf54l15"):
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: board)
    session = CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE,
                             board=name, baud=1_000_000,
                             ble_keys=keys, ble_filter=entries)
    session.open()
    return session


def test_keys_then_filter_then_start(monkeypatch):
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board, [KEY], [(1, IDENTITY)])
    names = board.sequence()
    assert names.index("BLE_KEYS") < names.index("BLE_FILTER") < names.index("START")


def test_both_lists_are_sent_even_when_empty(monkeypatch):
    """The nRF54L15 does not reset when its port opens, so a filter left
    from the last capture would otherwise still apply."""
    board = KeyedBoard("nrf54l15")
    open_session(monkeypatch, board)
    sent = {t: p for t, c, p in board.written if c is None}
    assert sent[FrameType.BLE_KEYS] == b""
    assert sent[FrameType.BLE_FILTER] == b""


def test_more_keys_than_the_board_holds_is_refused():
    keys = [DeviceKey(n, 0, f"11:22:33:44:55:{n:02x}", IRK) for n in range(6)]
    with pytest.raises(ValueError, match="holds 5"):
        CaptureSession("COM_UNUSED", channel=0, radio=Radio.BLE,
                       board="esp32c6", ble_keys=keys)
```

- [ ] **Step 3: Run the tests and check that they fail**

Run: `$PYTEST tests/test_ble_keys.py tests/test_ble_keys_capture.py -q`
Expected: ImportError for `filter_entries`, and for `hci_of_record` from `ble` (added in this task, below).

- [ ] **Step 4: Implement**

In `ble.py`, after `build_ble_record`:

```python
def hci_of_record(record: bytes) -> bytes:
    """The HCI packet inside a record from build_ble_record: the H4 type byte
    onwards, without the four-byte direction header."""
    return record[len(_DIRECTION_RECEIVED):]
```

In `ble_keys.py`, extend the control import to `from esp32c6_sniffer.control import (BLE_ADDRESS_PUBLIC, BLE_ADDRESS_RANDOM, MAX_BLE_FILTER, MAX_DEVICE_KEYS)` and add:

```python
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
```

In `capture.py`:
- Import `encode_ble_keys` beside `encode_ble_filter`.
- Add `from esp32c6_sniffer.boards import board_by_id` (check whether `boards` is already imported for `BRIDGED_BOARDS` and extend that import).
- Add the `ble_keys=None,` parameter after `ble_filter=None,` in `__init__`.
- After `self._ble_filter = list(ble_filter or [])` add:

```python
        #: Identity resolving keys for the controller's resolving list.
        self._ble_keys = list(ble_keys or [])
        if self._ble_keys:
            spec = board_by_id(board)
            if len(self._ble_keys) > spec["ble_keys"]:
                raise ValueError(
                    f"{len(self._ble_keys)} device keys, and the "
                    f"{spec['display']} holds {spec['ble_keys']}")
```

Replace the block in `_configure` that reads

```python
            if self._ble_filter:
                self._serial.write(encode_ble_filter(self._ble_filter))
                self._serial.flush()
```

with

```python
            self._send_ble_lists(self._ble_keys, self._ble_filter)
```

keeping the comment above it, and add the method after `_configure`:

```python
    def _send_ble_lists(self, keys, entries) -> None:
        """The device keys, then the accept list, both always.

        Always, even empty: an empty frame is how the board is told to clear
        one. The nRF54L15 does not reset when its port opens, so a list left
        from the previous capture would otherwise still apply -- a capture
        with no filter after one with a filter came out filtered anyway.

        Keys before the filter, and both before START: the board loads the
        resolving list, then the accept list that may name its identities,
        when the scan starts.
        """
        self._serial.write(encode_ble_keys(keys))
        self._serial.write(encode_ble_filter(entries))
        self._serial.flush()
```

- [ ] **Step 5: Run the tests and check that they pass, plus the existing BLE ones**

Run: `$PYTEST tests/test_ble_keys.py tests/test_ble_keys_capture.py tests/test_ble_filter.py tests/test_open_handshake.py tests/test_capture.py -q`
Expected: all pass. `test_open_handshake.py`'s `BridgedPort` ignores non-command frames, so the extra frames do not disturb it.

- [ ] **Step 6: Commit**

```bash
git add host/src/esp32c6_sniffer/ble.py host/src/esp32c6_sniffer/ble_keys.py \
        host/src/esp32c6_sniffer/capture.py host/tests/test_ble_keys.py \
        host/tests/test_ble_keys_capture.py
git commit -m "fix: the BLE filter follows random-address devices too

A typed address went to the accept list as public only, and the list
matches on type, so a random-address device was filtered out entirely:
0 reports against 10 on the C6. A plain address now takes both types; one
named in the device key file takes that identity's type.

The keys and the filter are now sent at every BLE start, empty when
unused, because the nRF54L15 keeps the last capture's lists in RAM.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Identity address types in the report parser

**Files:**
- Modify: `host/src/esp32c6_sniffer/adv.py` (`AddressType` about lines 84-115; `trackable` about line 188; `parse_advertising_reports` about line 240)
- Modify: `host/tests/test_adv.py`

**Interfaces:**
- Produces:
  - `AddressType.PUBLIC_IDENTITY = "public identity"` and `AddressType.RANDOM_IDENTITY = "random identity"`
  - `parse_hci_advertising_reports(hci: bytes) -> list[AdvertisingReport]` (hci starts with the H4 type byte)
  - `parse_advertising_reports(payload)` is unchanged in behaviour

- [ ] **Step 1: Write the failing tests** (append to `test_adv.py`, reusing its `extended()` helper and `MAC`)

```python
from esp32c6_sniffer.adv import AddressType, parse_hci_advertising_reports


def test_a_resolved_report_is_named_an_identity():
    """Types 2 and 3 are what a controller with the device's key reports.
    They were read as 'random static' by their top bits, which is wrong for
    a public identity and says nothing about the resolving."""
    public = parse_advertising_reports(extended(b"", address_type=0x02))[0]
    random = parse_advertising_reports(extended(b"", address_type=0x03))[0]
    assert public.address_type == AddressType.PUBLIC_IDENTITY
    assert random.address_type == AddressType.RANDOM_IDENTITY
    assert public.trackable and random.trackable


def test_hci_bytes_parse_without_the_frame_metadata():
    payload = extended(b"", address_type=0x03)
    assert parse_hci_advertising_reports(payload[12:]) == \
        parse_advertising_reports(payload)
```

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_adv.py -q`
Expected: ImportError for `parse_hci_advertising_reports`.

- [ ] **Step 3: Implement**

In `AddressType`, add the constants after `RANDOM_NON_RESOLVABLE`:

```python
    #: Reported by a controller that resolved the device with its key: the
    #: address shown is the identity, not what was sent on air.
    PUBLIC_IDENTITY = "public identity"
    RANDOM_IDENTITY = "random identity"
```

and at the top of `classify`:

```python
        if address_type == 0x02:
            return AddressType.PUBLIC_IDENTITY
        if address_type == 0x03:
            return AddressType.RANDOM_IDENTITY
```

In `trackable`, return true for all four stable kinds:

```python
        return self.address_type in (AddressType.PUBLIC,
                                     AddressType.RANDOM_STATIC,
                                     AddressType.PUBLIC_IDENTITY,
                                     AddressType.RANDOM_IDENTITY)
```

Split the parser:
- Rename the body of `parse_advertising_reports` from `hci = payload[META_LEN:]` onwards into `def parse_hci_advertising_reports(hci: bytes) -> list[AdvertisingReport]:`, starting at the `if len(hci) < 5 ...` check.
- Leave the wrapper as:

```python
def parse_advertising_reports(payload: bytes) -> list[AdvertisingReport]:
    """Decodes every report in one frame payload. Empty if it is not one."""
    if len(payload) <= META_LEN:
        return []
    return parse_hci_advertising_reports(payload[META_LEN:])
```

- [ ] **Step 4: Run the tests and check that they pass, plus the survey tools'**

Run: `$PYTEST tests/test_adv.py tests/test_survey_tools.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add host/src/esp32c6_sniffer/adv.py host/tests/test_adv.py
git commit -m "feat: the report parser names resolved identities

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Backwards-key watch, the Check keys tally, the silence watch, and their messages

**Files:**
- Modify: `host/src/esp32c6_sniffer/ble_keys.py`
- Modify: `host/tests/test_ble_keys.py`

**Interfaces:**
- Consumes: `parse_hci_advertising_reports`, `AddressType`, `resolves`.
- Produces:
  - `KeyFinding(key, reversed: bool, address: str)` with `.message(file_name) -> str`
  - `BackwardsKeyWatch(keys)`: `.observe(hci: bytes) -> list[KeyFinding]`, reporting each key at most once
  - `KeyCheck(keys)`: `.observe(hci: bytes) -> None` and `.results() -> list[KeyCheckResult]`
  - `KeyCheckResult(key, as_written: int, reversed: int)` with `.verdict` and `.message(file_name) -> str`
  - `KEY_CHECK_SECONDS = 20.0`
  - `SilenceWatch(identities, after_s: float = 30.0, start: float)`: `.observe(hci, at)` and `.silent(at) -> list[str]`, each identity reported once
  - `silence_message(identity: str, seconds: float) -> str`

- [ ] **Step 1: Write the failing tests** (append to `test_ble_keys.py`)

```python
from esp32c6_sniffer.ble_keys import (
    KEY_CHECK_SECONDS,
    BackwardsKeyWatch,
    KeyCheck,
    SilenceWatch,
    silence_message,
)


def report(address: str, address_type: int = 1) -> bytes:
    raw = bytes.fromhex(address.replace(":", ""))[::-1]
    body = bytearray([1, 0x10, 0x00, address_type]) + raw
    body += bytes([0x01, 0x00, 0x00, 0x7F, 0xC0, 0x00, 0x00, 0x00]) + bytes(6)
    body += bytes([0])
    return bytes([0x04, 0x3E, len(body) + 1, 0x0D]) + bytes(body)


BACKWARDS = DeviceKey(2, 1, IDENTITY, IRK[::-1])   # written the wrong way round


def test_a_backwards_key_is_spotted_once():
    watch = BackwardsKeyWatch([BACKWARDS])
    first = watch.observe(report(make_rpa(IRK, 0x400001)))
    assert [(f.key.line, f.reversed) for f in first] == [(2, True)]
    assert watch.observe(report(make_rpa(IRK, 0x400002))) == []


def test_a_correct_key_seen_unresolved_is_a_board_fault():
    [finding] = BackwardsKeyWatch([KEY]).observe(report(make_rpa(IRK, 0x400001)))
    assert not finding.reversed
    assert "board" in finding.message("keys.txt")


def test_resolved_and_static_addresses_are_not_tested():
    watch = BackwardsKeyWatch([BACKWARDS])
    assert watch.observe(report(IDENTITY, address_type=0x03)) == []
    assert watch.observe(report(IDENTITY, address_type=0x01)) == []


def test_the_backwards_message_names_the_line_and_never_the_key():
    [finding] = BackwardsKeyWatch([BACKWARDS]).observe(report(make_rpa(IRK, 0x400001)))
    text = finding.message("keys.txt")
    assert "line 2 of keys.txt" in text and "byte-reversed" in text
    assert IRK.hex() not in text and IRK[::-1].hex() not in text


def test_the_check_counts_distinct_addresses_per_key():
    check = KeyCheck([KEY, BACKWARDS, DeviceKey(3, 0, "11:22:33:44:55:66", bytes(range(1, 17)))])
    for prand in (0x400001, 0x400002, 0x400002):     # one repeated
        check.observe(report(make_rpa(IRK, prand)))
    verdicts = [(r.key.line, r.verdict, r.as_written, r.reversed) for r in check.results()]
    assert verdicts == [(1, "correct", 2, 0), (2, "backwards", 0, 2),
                        (3, "nothing matched", 0, 0)]


def test_check_messages_say_what_to_do():
    check = KeyCheck([BACKWARDS])
    check.observe(report(make_rpa(IRK, 0x400001)))
    [result] = check.results()
    text = result.message("keys.txt")
    assert "line 2" in text and "BACKWARDS" in text and IRK.hex() not in text


def test_the_check_listens_twenty_seconds():
    assert KEY_CHECK_SECONDS == 20.0


def test_silence_is_reported_once_after_thirty_seconds():
    watch = SilenceWatch([IDENTITY], start=100.0)
    assert watch.silent(129.0) == []
    watch.observe(report(IDENTITY, address_type=0x03), at=120.0)
    assert watch.silent(149.0) == []
    assert watch.silent(150.0) == [IDENTITY]
    assert watch.silent(500.0) == []


def test_the_silence_message_suggests_check_keys():
    text = silence_message(IDENTITY, 30.0)
    assert IDENTITY in text and "Check keys" in text
```

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: ImportError for `KEY_CHECK_SECONDS`.

- [ ] **Step 3: Implement** (append to `ble_keys.py`; add `from esp32c6_sniffer.adv import AddressType, parse_hci_advertising_reports` to the imports)

```python
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
```

- [ ] **Step 4: Run the tests and check that they pass**

Run: `$PYTEST tests/test_ble_keys.py -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add host/src/esp32c6_sniffer/ble_keys.py host/tests/test_ble_keys.py
git commit -m "feat: tell a backwards device key from a quiet device

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Check keys in the capture session

**Files:**
- Modify: `host/src/esp32c6_sniffer/capture.py`: `records()` (about lines 811-880), `__init__`, and new methods after `request_antenna`
- Modify: `host/tests/test_ble_keys_capture.py`

**Interfaces:**
- Consumes: `hci_of_record` (Task 4), `KEY_CHECK_SECONDS` (Task 6), `_send_ble_lists` (Task 4).
- Produces:
  - `CaptureSession.request_key_check(on_hci: Callable[[bytes], None], on_done: Callable[[], None], seconds: float = KEY_CHECK_SECONDS) -> bool`
  - `CaptureSession.key_check_running -> bool` (property)
  - `records()` behaves as before when no check is requested.

- [ ] **Step 1: Write the failing tests** (append to `test_ble_keys_capture.py`)

```python
def distinct(n: int) -> bytes:
    return ext_report(make_rpa(IRK, 0x400000 + n))


def test_what_is_heard_during_a_check_goes_to_the_check(monkeypatch):
    board = KeyedBoard("nrf54l15")
    session = open_session(monkeypatch, board, [KEY], [(1, IDENTITY)])
    a, b, c, d, e = (distinct(n) for n in range(1, 6))
    board.packet(a)
    board.before[Command.STOP] = [[b], [d]]    # in flight when STOP arrives
    board.after[Command.START] = [[c], [e]]    # heard after each START
    heard, done = [], []
    records = session.records()

    assert hci_of_record(next(records)[0]) == a
    assert session.request_key_check(heard.append, lambda: done.append(1),
                                     seconds=0.0)
    assert hci_of_record(next(records)[0]) == b      # before the STOP reply
    assert hci_of_record(next(records)[0]) == e      # after the restore
    assert heard == [c, d] and done == [1]


def test_the_check_clears_both_lists_then_restores_them(monkeypatch):
    board = KeyedBoard("nrf54l15")
    session = open_session(monkeypatch, board, [KEY], [(1, IDENTITY)])
    board.after[Command.START] = [[], [distinct(1)]]
    records = session.records()
    session.request_key_check(lambda hci: None, lambda: None, seconds=0.0)
    next(records)
    start = board.sequence().index("START") + 1        # after open()'s START
    assert board.sequence()[start:] == [
        "STOP", "BLE_KEYS", "BLE_FILTER", "START",
        "STOP", "BLE_KEYS", "BLE_FILTER", "START"]
    payloads = [p for t, c, p in board.written[start:] if c is None]
    assert payloads[0] == b"" and payloads[1] == b""
    assert payloads[2] != b"" and payloads[3] != b""


def test_a_second_request_while_one_runs_is_refused(monkeypatch):
    """Review focus 4: two presses must not stop and start twice."""
    session = open_session(monkeypatch, KeyedBoard("nrf54l15"), [KEY])
    assert session.request_key_check(lambda hci: None, lambda: None)
    assert not session.request_key_check(lambda hci: None, lambda: None)


def test_a_check_is_refused_on_a_radio_that_is_not_ble(monkeypatch):
    board = KeyedBoard("nrf54l15")
    monkeypatch.setattr(capture.serial, "Serial", lambda *a, **k: board)
    session = CaptureSession("COM_UNUSED", channel=11, radio=Radio.IEEE802154,
                             board="nrf54l15", baud=1_000_000)
    assert not session.request_key_check(lambda hci: None, lambda: None)


def test_stopping_during_a_check_ends_cleanly(monkeypatch):
    """Review focus 5: Wireshark closes the capture mid-check."""
    board = KeyedBoard("nrf54l15")
    session = open_session(monkeypatch, board, [KEY], [(1, IDENTITY)])
    board.packet(distinct(1))
    board.after[Command.START] = [[distinct(2)]]
    heard, done = [], []
    records = session.records()
    next(records)
    session.request_key_check(lambda hci: (heard.append(hci), session.request_stop()),
                              lambda: done.append(1), seconds=60.0)
    assert list(records) == []
    assert heard and done == []
```

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_ble_keys_capture.py -q`
Expected: `AttributeError: 'CaptureSession' object has no attribute 'request_key_check'`.

- [ ] **Step 3: Implement**

Imports in `capture.py`: `from dataclasses import dataclass` (if not already there), `from typing import Callable`, `from esp32c6_sniffer.ble import hci_of_record` (extend the existing `ble` import), and `from esp32c6_sniffer.ble_keys import KEY_CHECK_SECONDS`.

Module level, before `class CaptureSession`:

```python
@dataclass
class _KeyCheck:
    on_hci: Callable[[bytes], None]
    on_done: Callable[[], None]
    until: float
```

In `__init__`, after `self._pending_antenna: int | None = None`:

```python
        self._pending_check: tuple | None = None
        #: The Check keys listen in progress, or None.
        self._check: _KeyCheck | None = None
```

After `request_antenna`:

```python
    def request_key_check(self, on_hci, on_done,
                          seconds: float = KEY_CHECK_SECONDS) -> bool:
        """Listen with no keys and no filter for `seconds`, then put both back.

        From another thread; applied between reads like request_channel().
        What is heard meanwhile goes to on_hci (the HCI bytes) instead of
        the capture, and on_done() is called on the capture thread once the
        lists are restored. Returns False, and does nothing, if this is not
        a BLE capture or a check is already pending or running.

        The STOP replies are the boundaries: the board answers only after
        acting, and the stream is ordered, so a packet read before the reply
        was heard before the change.
        """
        if self._radio is not Radio.BLE:
            return False
        with self._pending_lock:
            if self._pending_check is not None or self._check is not None:
                return False
            self._pending_check = (on_hci, on_done, seconds)
        return True

    @property
    def key_check_running(self) -> bool:
        return self._check is not None or self._pending_check is not None

    def _key_check_step(self):
        """Starts or finishes a check. A generator, because packets heard
        before a STOP reply still belong to whichever side they came from."""
        with self._pending_lock:
            start = self._pending_check
            self._pending_check = None
        if start is not None:
            on_hci, on_done, seconds = start
            self._command(Command.STOP)
            before, self._deferred = self._deferred, []
            yield from self._records_from(before)
            self._check = _KeyCheck(on_hci, on_done,
                                    time.monotonic() + seconds)
            self._send_ble_lists([], [])
            self._command(Command.START)
        elif self._check is not None and time.monotonic() >= self._check.until:
            self._command(Command.STOP)
            heard, self._deferred = self._deferred, []
            for _ in self._records_from(heard):
                pass                    # routed to the check; yields nothing
            check, self._check = self._check, None
            self._send_ble_lists(self._ble_keys, self._ble_filter)
            self._command(Command.START)
            check.on_done()
```

Restructure `records()`. Move everything inside `for frame in frames:` into a new generator `_records_from(self, frames)`, unchanged except that just before `self.stats.frames += 1` it gains:

```python
                    if self._check is not None:
                        # Heard while Check keys listens: not the capture's.
                        self._check.on_hci(hci_of_record(record))
                        continue
```

`records()` then reads:

```python
        assert self._serial is not None, "call open() first"
        while self._serial is not None and not self._stop.is_set():
            yield from self._key_check_step()
            self._apply_pending()
            chunk = self._serial.read(8192)
            frames = self._deferred + self._parser.feed(chunk)
            self._deferred = []
            if not frames:
                continue
            yield from self._records_from(frames)
```

`_records_from` has a `for frame in frames:` loop containing the previous body verbatim. Its `continue` statements stay valid because they are inside that loop.

- [ ] **Step 4: Run the tests and check that they pass, then the whole suite**

Run: `$PYTEST tests/test_ble_keys_capture.py -q`, then `$PYTEST -q`
Expected: all pass. The refactor must not change any existing capture test.

- [ ] **Step 5: Commit**

```bash
git add host/src/esp32c6_sniffer/capture.py host/tests/test_ble_keys_capture.py
git commit -m "feat: a capture can listen without its keys for a moment, to check them

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Wireshark: the Device keys option, the Check keys button, and the warnings

**Files:**
- Modify: `extcap/esp32c6-sniffer.py`:
  - the `CTRL_ARG_*` constants (about line 302)
  - the toolbar controls (about lines 470-489)
  - the BLE options (about lines 648-661)
  - `do_capture` signature (about line 822), key reading (about line 862), `log` (about line 906), `reader` (about line 910), the filter parse (about line 1075), `CaptureSession(...)` (about line 1084), the heartbeat (about line 1142) and the record loop (about line 1163)
  - argparse (about line 1343) and the `do_capture` call (about line 1441)
- Modify: `host/tests/test_extcap.py`, `host/tests/test_shutdown.py`

**Interfaces:**
- Consumes: `parse_key_file`, `KeyFileError`, `filter_entries`, `BackwardsKeyWatch`, `KeyCheck`, `SilenceWatch`, `silence_message`, `KEY_CHECK_SECONDS`, `hci_of_record`, and `CaptureSession(ble_keys=...)` / `request_key_check`.
- Produces: `--ble-keys <path>` (arg number 8) and toolbar control `CTRL_ARG_CHECK_KEYS = 3`.

- [ ] **Step 1: Write the failing tests**

Append to `host/tests/test_extcap.py`:

```python
def test_ble_offers_a_device_key_file():
    out = _run("--extcap-config", "--extcap-interface", BLE_INTERFACE)
    line = next(l for l in out.splitlines() if "--ble-keys" in l)
    assert "{type=fileselect}" in line and "secret" in line
    assert "never written into the capture" in line


def test_the_filter_tooltip_no_longer_promises_eight_addresses():
    out = _run("--extcap-config", "--extcap-interface", BLE_INTERFACE)
    line = next(l for l in out.splitlines() if "--ble-filter" in l)
    assert "up to eight addresses" not in line and "four" in line


def test_the_toolbar_has_a_check_keys_button():
    out = _run("--extcap-interfaces")
    assert any("{number=3}" in l and "{type=button}" in l and "Check keys" in l
               for l in out.splitlines())


def test_a_bad_device_key_file_stops_the_capture_before_it_starts(tmp_path):
    keys = tmp_path / "keys.txt"
    keys.write_text("not a key file\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(PLUGIN), "--capture", "--extcap-interface",
         BLE_INTERFACE, "--fifo", str(tmp_path / "out.pcapng"),
         "--ble-keys", str(keys)],
        capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert "keys.txt line 1" in result.stderr
    assert "not a key file" not in result.stderr
```

Append to `host/tests/test_shutdown.py`:

```python
def test_the_toolbar_reader_starts_a_key_check(do_capture):
    reader = function_in(do_capture, "reader")
    assert "CTRL_ARG_CHECK_KEYS" in ast.unparse(reader)
    assert calls(do_capture, "request_key_check")


def test_typed_addresses_go_through_filter_entries(do_capture):
    """The measured bug was bare strings reaching the accept list as public."""
    assert calls(do_capture, "filter_entries")


def test_the_silence_watch_is_checked_from_the_heartbeat(do_capture):
    """A filtered capture of a silent device yields no records, so a check
    that ran only in the record loop would never run."""
    assert calls(function_in(do_capture, "heartbeat"), "silent")
```

- [ ] **Step 2: Run the tests and check that they fail**

Run: `$PYTEST tests/test_extcap.py tests/test_shutdown.py -q`
Expected: the new tests fail (StopIteration or assertion errors).

- [ ] **Step 3: Implement**

Constants, after `CTRL_ARG_LOGGER = 2`:

```python
CTRL_ARG_CHECK_KEYS = 3
```

Toolbar, after the logger control `print(...)`:

```python
    from esp32c6_sniffer.ble_keys import KEY_CHECK_SECONDS
    print(f"control {{number={CTRL_ARG_CHECK_KEYS}}}{{type=button}}"
          f"{{display=Check keys}}"
          f"{{tooltip=BLE with a device key file: listens "
          f"{KEY_CHECK_SECONDS:.0f} s with no keys and no filter, then says "
          f"for each key whether it is right, backwards, or matched nothing. "
          f"Those seconds are left out of the capture}}")
```

The import is local, following the extcap's existing habit of importing the package inside the function that needs it.

Replace the `--ble-filter` tooltip text with:

```python
                  "{tooltip=Restricts scanning to these devices, filtered by "
                  "the controller so the rest never cross the USB link. An "
                  "address in the Device keys file is followed through its "
                  "address changes and takes one of the eight places; any "
                  "other address takes two, because whether it is public or "
                  "random cannot be told from the address, so four fit. Leave "
                  "empty to hear everything}")
```

After the `--ble-filter` print, inside the same `if board_for_interface(interface)["ble_filter"]:`:

```python
            holds = board_for_interface(interface)["ble_keys"]
            print("arg {number=8}{call=--ble-keys}{display=Device keys}"
                  "{type=fileselect}{fileext=Key files (*.txt)}"
                  "{tooltip=Identity resolving keys, so a device that changes "
                  "its address is recognised under every address it uses and "
                  "shown under its fixed identity address. One per line: the "
                  "identity address, optionally public or random (public if "
                  "left out), then the key as 32 hex digits. The file is a "
                  "secret: anyone holding it can follow those devices. The "
                  "keys go to the board's memory for this capture only and "
                  "are never written into the capture file. This board holds "
                  f"{holds}. Check keys on the toolbar says whether each key "
                  "is right}")
```

argparse, after `--ble-filter`:

```python
    parser.add_argument("--ble-keys", dest="ble_keys_file", default=None)
```

and pass `ble_keys_file=args.ble_keys_file,` in the `do_capture(...)` call.

`do_capture` gains the keyword `ble_keys_file: str | None = None`. After the Zigbee key block (before the Thread block), add:

```python
    # Device keys and the filter, read on the same terms as the Zigbee keys:
    # a bad file must fail while Wireshark can still show why. The filter is
    # read here too because keyed identities decide how it is typed.
    device_keys = []
    key_name = os.path.basename(ble_keys_file) if ble_keys_file else ""
    accept = []
    if radio is Radio.BLE:
        from esp32c6_sniffer.ble_keys import (
            KeyFileError, filter_entries, parse_key_file,
        )
        if ble_keys_file:
            try:
                device_keys = parse_key_file(ble_keys_file)
            except KeyFileError as exc:
                sys.stderr.write(str(exc) + os.linesep)
                return 1
            holds = board_for_interface(interface)["ble_keys"]
            if len(device_keys) > holds:
                sys.stderr.write(
                    f"{key_name} holds {len(device_keys)} device keys and "
                    f"this board holds {holds}" + os.linesep)
                return 1
        if ble_filter:
            typed = [a for a in ble_filter.replace(",", " ").split() if a]
            try:
                accept = filter_entries(typed, device_keys)
            except ValueError as exc:
                sys.stderr.write(str(exc) + os.linesep)
                return 1
```

Delete the old `filter_addresses` block (about lines 1075-1079) and pass `ble_filter=accept, ble_keys=device_keys,` to `CaptureSession(...)`.

Replace `log()` with a locked version, since three threads now write the control pipe:

```python
    control_lock = threading.Lock()

    def log(text: str, popup: bool = False) -> None:
        if not state["initialized"]:
            return
        with control_lock:
            control_write(fp_out, CTRL_ARG_LOGGER, CTRL_CMD_ADD,
                          text.encode("utf-8") + b"\n")
            if popup:
                control_write(fp_out, CTRL_ARG_NONE, CTRL_CMD_INFORMATION,
                              text.encode("utf-8"))
```

In `reader`, after the antenna branch:

```python
            if cmd == CTRL_CMD_SET and arg == CTRL_ARG_CHECK_KEYS:
                start_key_check(session)
                continue
```

Define it before `reader`:

```python
    def start_key_check(session) -> None:
        if radio is not Radio.BLE or not device_keys:
            log("Check keys: needs a BLE capture with a Device keys file")
            return
        from esp32c6_sniffer.ble_keys import KEY_CHECK_SECONDS, KeyCheck
        check = KeyCheck(device_keys)

        def done() -> None:
            # One log line per key, and one pop-up holding all of them --
            # not a pop-up per key, which would stack up dialogs.
            lines = [r.message(key_name) for r in check.results()]
            for line in lines:
                log(line)
            with control_lock:
                control_write(fp_out, CTRL_ARG_NONE, CTRL_CMD_INFORMATION,
                              "\n".join(lines).encode("utf-8"))

        if session.request_key_check(check.observe, done):
            log(f"Check keys: listening {KEY_CHECK_SECONDS:.0f} s with no keys "
                f"and no filter; those packets are left out of the capture")
        else:
            log("Check keys: a check is already running")
```

Watches, created just before the `with CaptureSession(...)`:

```python
        backwards = silence = None
        if device_keys:
            from esp32c6_sniffer.ble import hci_of_record
            from esp32c6_sniffer.ble_keys import (
                BackwardsKeyWatch, SilenceWatch, silence_message,
            )
            backwards = BackwardsKeyWatch(device_keys)
            followed = [k.address for k in device_keys
                        if any(address == k.address for _, address in accept)]
            if followed:
                silence = SilenceWatch(followed, start=time.monotonic())
```

In the record loop, after `note = None`:

```python
                    if backwards is not None:
                        hci = hci_of_record(record)
                        for finding in backwards.observe(hci):
                            text = finding.message(key_name)
                            log(text, popup=True)
                            note = text if note is None else f"{note}; {text}"
                        if silence is not None:
                            silence.observe(hci, time.monotonic())
```

In `heartbeat`, after the statistics write succeeds:

```python
                    if silence is not None:
                        for identity in silence.silent(time.monotonic()):
                            log(silence_message(identity, 30.0))
```

- [ ] **Step 4: Run the tests and check that they pass, then the whole suite**

Run: `$PYTEST tests/test_extcap.py tests/test_shutdown.py tests/test_key_file.py -q`, then `$PYTEST -q`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add extcap/esp32c6-sniffer.py host/tests/test_extcap.py host/tests/test_shutdown.py
git commit -m "feat: device keys and Check keys, from Wireshark

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: ESP32-C6 firmware: frame 15, the resolving list, version 7

**Files:**
- Modify: `firmware/main/radio_ble.c`:
  - opcodes, about line 25
  - key storage beside `s_filter`, about line 97
  - `sn_radio_ble_set_keys` beside `sn_radio_ble_set_filter`, about line 364
  - `apply_keys()` called at the top of `apply_filter()`, about line 389
  - clear in `sn_radio_ble_stop()`, about line 553
  - a stub in the `#else` region, about line 692
- Modify: `firmware/main/radio_ble.h` (declaration beside `sn_radio_ble_set_filter`, about line 100)
- Modify: `firmware/main/control.h` and `firmware/main/control.c` (handler type, setter, dispatch)
- Modify: `firmware/main/main.c` (version history and 7, about line 77; `on_ble_keys` inside the capture guard, about line 426; registration, about line 510)
- Modify: `firmware/sdkconfig.defaults`
- Modify: `host/src/esp32c6_sniffer/capture.py` (`EXPECTED_FIRMWARE_VERSIONS["esp32c6"] = 7`)

**Interfaces:**
- Consumes: `SN_FRAME_BLE_KEYS` (Task 3).
- Produces: firmware version 7, which accepts frame 15.

- [ ] **Step 1: Check the version is still free**

Run: `grep -n "SN_FIRMWARE_VERSION" firmware/main/main.c && grep -n '"esp32c6":' host/src/esp32c6_sniffer/capture.py`
Expected: 6 in both. If either moved, use the next number above the higher one everywhere below.

- [ ] **Step 2: Implement**

`radio_ble.c` opcodes, after `OPCODE_LE_ADD_TO_ACCEPT_LIST`:

```c
#define OPCODE_LE_ADD_TO_RESOLVING_LIST 0x2027
#define OPCODE_LE_CLEAR_RESOLVING_LIST  0x2029
#define OPCODE_LE_SET_ADDR_RESOLUTION   0x202D
#define OPCODE_LE_SET_PRIVACY_MODE      0x204E
```

Storage, after `static uint8_t s_filter_count;`:

```c
/* Identity resolving keys: N x (identity type, identity address, key), both
 * least significant first, exactly as the host frames them. Held for one
 * capture and cleared when it stops; never logged. The controller's
 * resolving list is the limit, and its Kconfig caps it at five. */
#define SN_BLE_KEY_ENTRY 23u
#define SN_BLE_MAX_KEYS CONFIG_BT_LE_LL_RESOLV_LIST_SIZE
static uint8_t s_keys[SN_BLE_MAX_KEYS][SN_BLE_KEY_ENTRY];
static uint8_t s_key_count;
```

After `sn_radio_ble_filter_count`:

```c
esp_err_t sn_radio_ble_set_keys(const uint8_t *entries, size_t len)
{
    if (len % SN_BLE_KEY_ENTRY != 0u) {
        return ESP_ERR_INVALID_SIZE;
    }
    const size_t count = len / SN_BLE_KEY_ENTRY;
    if (count > SN_BLE_MAX_KEYS) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < count; i++) {
        if (entries[i * SN_BLE_KEY_ENTRY] > 1u) {
            return ESP_ERR_INVALID_ARG;
        }
    }
    memset(s_keys, 0, sizeof(s_keys));
    memcpy(s_keys, entries, len);
    s_key_count = (uint8_t)count;
    ESP_LOGI(TAG, "device keys: %u", s_key_count);
    return ESP_OK;
}

/* Loads the resolving list: resolution off (the list cannot change while it
 * is on), clear, each key with device privacy mode, then resolution on.
 *
 * Device privacy mode because the default, network privacy mode, drops an
 * advertisement from a listed device that uses its identity address instead
 * of a private one, and a sniffer should hear those too.
 *
 * The local IRK is left zero: the sniffer has no identity of its own. */
static esp_err_t apply_keys(void)
{
    const uint8_t off = 0x00;
    const uint8_t on = 0x01;
    esp_err_t err = send_command(OPCODE_LE_SET_ADDR_RESOLUTION, &off, 1);
    if (err != ESP_OK) {
        return err;
    }
    err = send_command(OPCODE_LE_CLEAR_RESOLVING_LIST, NULL, 0);
    if (err != ESP_OK) {
        return err;
    }
    for (uint8_t i = 0; i < s_key_count; i++) {
        uint8_t entry[SN_BLE_KEY_ENTRY + 16u] = {0};
        memcpy(entry, s_keys[i], SN_BLE_KEY_ENTRY);
        err = send_command(OPCODE_LE_ADD_TO_RESOLVING_LIST, entry,
                           sizeof(entry));
        if (err != ESP_OK) {
            return err;
        }
        uint8_t mode[8];
        memcpy(mode, s_keys[i], 7u);        /* type and identity address */
        mode[7] = 0x01;                     /* device privacy mode */
        err = send_command(OPCODE_LE_SET_PRIVACY_MODE, mode, sizeof(mode));
        if (err != ESP_OK) {
            return err;
        }
    }
    if (s_key_count > 0u) {
        err = send_command(OPCODE_LE_SET_ADDR_RESOLUTION, &on, 1);
    }
    return err;
}
```

At the top of `apply_filter()`, before clearing the accept list:

```c
    /* Keys first: the accept list may name identities that only the
     * resolving list can recognise. */
    esp_err_t err = apply_keys();
    if (err != ESP_OK) {
        return err;
    }
    err = send_command(OPCODE_LE_CLEAR_ACCEPT_LIST, NULL, 0);
```

This replaces the existing `esp_err_t err = send_command(OPCODE_LE_CLEAR_ACCEPT_LIST, NULL, 0);`.

In `sn_radio_ble_stop()`, after `s_sync_count = 0;`:

```c
    /* Keys are secrets; they live for one capture. */
    memset(s_keys, 0, sizeof(s_keys));
    s_key_count = 0;
```

In the `#else /* !CONFIG_BT_ENABLED */` region:

```c
esp_err_t sn_radio_ble_set_keys(const uint8_t *entries, size_t len)
{
    (void)entries; (void)len;
    return ESP_ERR_NOT_SUPPORTED;
}
```

`radio_ble.h`, after `sn_radio_ble_filter_count`:

```c
/* Identity resolving keys: N x 23 bytes, (identity type, identity address,
 * key), the last two least significant first. Refuses a malformed payload,
 * more keys than the resolving list holds, or a type other than 0 or 1.
 * Takes effect at the next scan start and is cleared when the scan stops. */
esp_err_t sn_radio_ble_set_keys(const uint8_t *entries, size_t len);
```

`control.h`, after the filter handler:

```c
/* Called for a SN_FRAME_BLE_KEYS frame: N x (identity type, identity address,
 * key), least significant first. Key material: never log the payload. */
typedef void (*sn_ble_keys_handler_t)(const uint8_t *payload, size_t len);
void sn_control_set_ble_keys_handler(sn_ble_keys_handler_t handler);
```

`control.c`:
- Declare `static sn_ble_keys_handler_t s_ble_keys_handler;` beside the filter handler's variable.
- In `parse_buffered`, after the `SN_FRAME_BLE_FILTER` branch, add:

```c
        } else if (s_buf[2] == SN_FRAME_BLE_KEYS &&
                   s_ble_keys_handler != NULL) {
            s_ble_keys_handler(s_buf + SN_HEADER_LEN, payload_len);
```

- After `sn_control_set_ble_filter_handler`, add:

```c
void sn_control_set_ble_keys_handler(sn_ble_keys_handler_t handler)
{
    s_ble_keys_handler = handler;
}
```

`main.c`:
- Add `" *   7: BLE device keys (SN_FRAME_BLE_KEYS) and the resolving list"` to the version history and set `#define SN_FIRMWARE_VERSION 7u`.
- Inside `#if SN_MODE == SN_MODE_CAPTURE`, after `on_ble_filter`:

```c
static void on_ble_keys(const uint8_t *payload, size_t len)
{
    const esp_err_t err = sn_radio_ble_set_keys(payload, len);
    if (err != ESP_OK) {
        /* The size and the reason; the payload is key material. */
        ESP_LOGW(TAG, "device keys rejected (%u bytes): %s", (unsigned)len,
                 esp_err_to_name(err));
    }
}
```

- Register it after `sn_control_set_ble_filter_handler(on_ble_filter);` with `sn_control_set_ble_keys_handler(on_ble_keys);`.

`sdkconfig.defaults`, after `CONFIG_BT_BLE_ENABLED=y`:

```
# Identity resolving keys, for following a device that changes its address.
# Five is this controller's Kconfig maximum (range 1 to 5, default 4). The
# host reads the same number from boards.py "ble_keys".
CONFIG_BT_LE_LL_RESOLV_LIST_SIZE=5
```

`capture.py`: `"esp32c6": 7,` in `EXPECTED_FIRMWARE_VERSIONS`.

- [ ] **Step 3: Build the capture build and the conformance build (pwsh)**

`firmware/sdkconfig` is untracked and generated. Delete it so the new default applies, then build:

```powershell
Set-Location G:\dev\projects\esp32c6-sniffer-keys\firmware
Remove-Item sdkconfig -ErrorAction SilentlyContinue
. .\idf-env.ps1
idf.py -DSN_MODE=0 build 2>&1 | Select-String "error|Project build complete" | Select-Object -Last 3
idf.py -DSN_MODE=2 build 2>&1 | Select-String "error|Project build complete" | Select-Object -Last 3
Select-String -Path sdkconfig -Pattern "LL_RESOLV_LIST_SIZE"
```

Expected: both say "Project build complete", and the setting reads `CONFIG_BT_LE_LL_RESOLV_LIST_SIZE=5`. The second build is the capture build that Task 13 flashes.

- [ ] **Step 4: Run the host suite, then commit**

Run: `$PYTEST -q`
Expected: all pass. Any test pinning the C6 version to 6 must be updated to read `EXPECTED_FIRMWARE_VERSIONS`.

```bash
git add firmware/main/radio_ble.c firmware/main/radio_ble.h firmware/main/control.c \
        firmware/main/control.h firmware/main/main.c firmware/sdkconfig.defaults \
        host/src/esp32c6_sniffer/capture.py
git commit -m "feat(c6): device keys go into the controller's resolving list (firmware 7)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: nRF54L15: HCI commands report the controller's answer

**Files:**
- Modify: `nrf:src/radio_ble.c`: includes; `send_command()` about line 158; `fwd_loop()` about line 408

**Interfaces:**
- Produces:
  - `hci_command(opcode, params, len, uint8_t *status)` returns 0 only when the controller accepted the command, otherwise `-EIO` (refused, status in `*status`), `-ETIMEDOUT` (no answer in 2 s) or `bt_send()`'s error. It does not log a refusal.
  - `send_command(opcode, params, len)` is `hci_command()` that logs a refusal. Setup paths use it.
  - The periodic sync worker uses `hci_command()`: a duplicate-sync refusal is ordinary there, and it happens for every repeat of an advertisement.
  - BIG Create Sync moves to a work item. It was sent from the forwarding thread, which is the thread that delivers the answer, so waiting there would deadlock.
  - A START with any refused step replies `SN_STATUS_FAILED`.
- Behaviour change to note in the commit: a refused periodic Create Sync no longer counts toward `MAX_SYNCS`. Before, every call counted because `bt_send()` always succeeded, so duplicate requests used up slots.

- [ ] **Step 1: Message the other session and wait for its answer**

Message "Bluetooth exploration status": *"About to edit nrf src/radio_ble.c (send_command and fwd_loop) in the nrf54l15-sniffer-keys worktree. Is your counter-reset change touching those functions?"* If it is, agree an order before editing.

- [ ] **Step 2: Show the defect on the board first (needs COM4, message sent)**

On the current nRF firmware 4, the controller refuses a scan whose PHY bitmap holds the 2M bit, and nothing notices. With `firmware/` untouched on the board, run this from the **main** checkout's host (which still expects nRF 4):

```bash
cd /g/dev/projects/esp32c6-sniffer/host
.venv/Scripts/python.exe -c "
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Radio
s = CaptureSession('COM4', channel=0, radio=Radio.BLE, board='nrf54l15', baud=1000000, ble_phys=2)
s.open(); print('opened: the refusal went unnoticed'); s.close()"
```

Expected before the fix: `opened: the refusal went unnoticed`.

Record the stale filter here too, while the board still runs firmware 4 and the main checkout's host. Run the scratch script from the filter-type measurement twice:

```bash
cd /g/dev/projects/esp32c6-sniffer/host
.venv/Scripts/python.exe <scratchpad>/filter_type_check.py COM4 nrf54l15 20
.venv/Scripts/python.exe <scratchpad>/filter_type_check.py COM4 nrf54l15 20
```

The script ends with a filtered capture. If the second run's first line ("unfiltered 20 s: … addresses") shows one address, the nRF kept the previous capture's filter: the stale filter is confirmed. Record the numbers (no addresses) for the Task 4 commit history and the README.

- [ ] **Step 3: Implement**

At the top of `radio_ble.c`, after the includes:

```c
#include <zephyr/logging/log.h>

LOG_MODULE_REGISTER(radio_ble, LOG_LEVEL_INF);
```

Beside the other statics:

```c
/* The command in flight and what the controller said about it. One at a
 * time: the lock serialises the control path against the sync worker. */
static K_MUTEX_DEFINE(cmd_lock);
static K_SEM_DEFINE(cmd_done, 0, 1);
static volatile uint16_t pending_opcode;
static volatile uint8_t pending_status;

/* Picks the answer to our own command out of the event stream. Command
 * Complete puts the opcode at 3 and the status at 5; Command Status puts the
 * status at 2 and the opcode at 4. */
static void note_command_result(const uint8_t *evt, uint16_t len)
{
	uint16_t opcode;
	uint8_t status;

	if (evt[0] == BT_HCI_EVT_CMD_COMPLETE && len >= 6u) {
		opcode = sys_get_le16(evt + 3);
		status = evt[5];
	} else if (evt[0] == BT_HCI_EVT_CMD_STATUS && len >= 6u) {
		status = evt[2];
		opcode = sys_get_le16(evt + 4);
	} else {
		return;
	}
	if (opcode == 0u || opcode != pending_opcode) {
		return;
	}
	pending_status = status;
	pending_opcode = 0u;
	k_sem_give(&cmd_done);
}
```

Replace `send_command()` with the pair below.

**Must not be called from the forwarding thread.** That thread delivers the answer, so it would wait for itself (see the BIG change after this).

```c
/* Sends one HCI command and waits for the controller's answer to it:
 * 0 accepted, -EIO refused (its status in *status if given), -ETIMEDOUT no
 * answer, or bt_send()'s own error. Does not log a refusal -- for a caller
 * like the sync worker a refusal is ordinary.
 *
 * This used to send, sleep 20 ms and return bt_send()'s result, which says
 * only that the buffer was queued. A command the controller REFUSED was
 * never noticed: a scan with an impossible PHY bitmap started "fine" and
 * captured nothing. Waiting for the answer also replaces the sleep that
 * kept us inside one outstanding command.
 *
 * Never call this from the forwarding thread: that thread delivers the
 * answer, so it would wait for itself. */
static int hci_command(uint16_t opcode, const uint8_t *params, uint8_t len,
		       uint8_t *status)
{
	k_mutex_lock(&cmd_lock, K_FOREVER);

	struct net_buf *buf = bt_buf_get_tx(BT_BUF_CMD, K_SECONDS(1), NULL, 0);

	if (buf == NULL) {
		k_mutex_unlock(&cmd_lock);
		return -ENOBUFS;
	}

	/* The command header goes in the buffer; only the H4 type byte is
	 * carried out of band, as the buffer's type. */
	struct bt_hci_cmd_hdr *hdr = net_buf_add(buf, sizeof(*hdr));

	hdr->opcode = sys_cpu_to_le16(opcode);
	hdr->param_len = len;
	if (len > 0u) {
		net_buf_add_mem(buf, params, len);
	}

	k_sem_reset(&cmd_done);
	pending_status = 0xFFu;
	pending_opcode = opcode;

	int err = bt_send(buf);

	if (err == 0 && k_sem_take(&cmd_done, K_SECONDS(2)) != 0) {
		LOG_ERR("HCI opcode 0x%04x never completed", opcode);
		err = -ETIMEDOUT;
	} else if (err == 0 && pending_status != 0u) {
		err = -EIO;
	}
	if (status != NULL) {
		*status = pending_status;
	}
	pending_opcode = 0u;
	k_mutex_unlock(&cmd_lock);
	return err;
}

/* hci_command(), with a refusal logged: during setup every refusal is a
 * fault somebody needs to see. */
static int send_command(uint16_t opcode, const uint8_t *params, uint8_t len)
{
	uint8_t status = 0u;
	const int err = hci_command(opcode, params, len, &status);

	if (err == -EIO) {
		LOG_ERR("HCI opcode 0x%04x refused, status 0x%02x", opcode,
			status);
	}
	return err;
}
```

In `sync_work_fn`, change the Create Sync call to the quiet form. Its existing comment already says why a refusal is ordinary there:

```c
		if (hci_command(BT_HCI_OP_LE_PER_ADV_CREATE_SYNC,
				params, sizeof(params), NULL) == 0) {
			sync_count++;
		}
```

Move BIG Create Sync off the forwarding thread. Just above `note_biginfo()`, add:

```c
/* BIG Create Sync, handed to a work item for the reason sync requests are.
 * note_biginfo() runs on the forwarding thread, which is also the thread
 * that delivers the controller's answer: waiting for it there would wait
 * for itself, time out after two seconds, and never join a broadcast. */
static uint8_t big_params[25 + MAX_BIS];
static uint8_t big_len;
static atomic_t big_pending;
static void big_work_fn(struct k_work *work);
static K_WORK_DEFINE(big_work, big_work_fn);

static void big_work_fn(struct k_work *work)
{
	ARG_UNUSED(work);

	if (hci_command(BT_HCI_OP_LE_BIG_CREATE_SYNC, big_params, big_len,
			NULL) == 0) {
		big_synced = true;
	}
	atomic_clear(&big_pending);
}
```

At the end of `note_biginfo()`, replace

```c
	if (send_command(BT_HCI_OP_LE_BIG_CREATE_SYNC, params, n) == 0) {
		big_synced = true;
	}
```

with

```c
	/* One request in flight is enough: every BIGInfo repeats until the
	 * sync is made. */
	if (!atomic_cas(&big_pending, 0, 1)) {
		return;
	}
	memcpy(big_params, params, n);
	big_len = n;
	k_work_submit(&big_work);
```

Afterwards, check that nothing else on the forwarding thread sends a command: `grep -n "send_command\|hci_command" src/radio_ble.c`. Every remaining call must be in `sn_radio_ble_start`, `apply_filter`, `apply_keys` (Task 11), `sn_radio_ble_stop`, `sync_work_fn` or `big_work_fn`, never in a `note_*` function or in `forward`.

In `fwd_loop`, right after `const uint8_t h4 = net_buf_pull_u8(buf);`:

```c
		/* Our own commands' answers, before the capture filter below
		 * drops them: send_command() is waiting on one. */
		if (h4 == BT_HCI_H4_EVT && buf->len >= 2u) {
			note_command_result(buf->data, buf->len);
		}
```

- [ ] **Step 4: Build**

Run in pwsh: `& <scratchpad>\nrf_build.ps1 -Ncs G:\dev\tools\ncs -App G:\dev\projects\nrf54l15-sniffer-keys -Build G:\dev\scratch\nrf\bkeys`
Expected: `exit 0` and no `error`. (The version is still 4 here; Task 11 bumps it.)

- [ ] **Step 5: Show the fix on the board**

Flash with `& <scratchpad>\nrf_flash_verify.ps1 -Build G:\dev\scratch\nrf\bkeys` (expected: `verified`). Re-run the Step 2 command.

Expected: `RuntimeError: START failed, status 3`. Then run an ordinary 20 s unfiltered BLE capture with `ble_phys` left at its default, and check that reports still arrive. Use `<scratchpad>/irk_spike_capture.py COM4 nrf54l15 20 nofilter` or `host/tools/ble_survey.py`: expected hundreds of reports, as before.

- [ ] **Step 6: Commit (nRF worktree)**

```bash
cd /g/dev/projects/nrf54l15-sniffer-keys
git add src/radio_ble.c
git commit -m "fix: HCI commands report whether the controller accepted them

send_command() returned bt_send()'s result, which says only that the
buffer was queued. A refused command -- a scan with the 2M bit in its PHY
bitmap, measured -- started fine and captured nothing. It now waits for
the Command Complete or Command Status and returns its status.

BIG Create Sync moves to a work item: it was sent from the thread that
delivers the answer, which would now wait for itself. A refused periodic
Create Sync no longer counts toward MAX_SYNCS; duplicate requests used to
use up slots because every send counted as accepted.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: nRF54L15 firmware: frame 15, the resolving list, version 5

**Files:**
- Modify: `nrf:shared` (submodule pointer, to the Task 3 commit)
- Modify: `nrf:src/radio_ble.c` (storage beside `filter`, about line 61; `sn_radio_ble_set_keys` beside `sn_radio_ble_set_filter`, about line 709; `apply_keys()` and its call in `apply_filter()`, about line 723; clear in `sn_radio_ble_stop()`, about line 740)
- Modify: `nrf:src/radio_ble.h`, `nrf:src/control.c` (about line 77), `nrf:src/main.c` (about line 21), `nrf:prj.conf`
- Modify: `host/src/esp32c6_sniffer/capture.py` (`"nrf54l15": 5`)

**Interfaces:**
- Consumes: `send_command()` status (Task 10), `SN_FRAME_BLE_KEYS` (Task 3).
- Produces: nRF firmware 5, which accepts frame 15.

- [ ] **Step 1: Point the nRF worktree's `shared` at the new frame type, and check the version is still free**

```bash
cd /g/dev/projects/nrf54l15-sniffer-keys/shared
git fetch /g/dev/projects/esp32c6-sniffer-keys/shared ble-keys-frame
git checkout -b ble-keys-frame FETCH_HEAD
grep -n "SN_FRAME_BLE_KEYS" frame.h
cd .. && grep -n "define SN_FIRMWARE_VERSION" src/main.c
```

Expected: `SN_FRAME_BLE_KEYS = 15` is present, and the version is 4. If it moved, use the next free number.

- [ ] **Step 2: Implement**

`radio_ble.c` storage, after `static uint8_t filter_count;`:

```c
/* Identity resolving keys: N x (identity type, identity address, key), both
 * least significant first, exactly as the host frames them. Held for one
 * capture, cleared when it stops, never logged. */
#define KEY_ENTRY 23u
#define MAX_KEYS CONFIG_BT_CTLR_RL_SIZE
static uint8_t keys[MAX_KEYS][KEY_ENTRY];
static uint8_t key_count;
```

After `sn_radio_ble_set_filter`:

```c
int sn_radio_ble_set_keys(const uint8_t *payload, size_t len)
{
	/* Refused whole rather than truncated: a key silently dropped is a
	 * device silently not followed. */
	if (len % KEY_ENTRY != 0u || len / KEY_ENTRY > MAX_KEYS) {
		LOG_WRN("device keys rejected: %u bytes", (unsigned)len);
		return -EINVAL;
	}
	for (size_t i = 0; i < len; i += KEY_ENTRY) {
		if (payload[i] > 1u) {
			LOG_WRN("device keys rejected: address type %u",
				payload[i]);
			return -EINVAL;
		}
	}
	memset(keys, 0, sizeof(keys));
	memcpy(keys, payload, len);
	key_count = (uint8_t)(len / KEY_ENTRY);
	LOG_INF("device keys: %u", key_count);
	return 0;
}

/* Loads the resolving list: resolution off (the list cannot change while it
 * is on), clear, each key with device privacy mode, then resolution on.
 * Device privacy mode so a listed device advertising under its identity
 * address is still heard; the default drops it. The local IRK stays zero:
 * the sniffer has no identity. */
static int apply_keys(void)
{
	const uint8_t off = 0x00u;
	const uint8_t on = 0x01u;
	int err = send_command(BT_HCI_OP_LE_SET_ADDR_RES_ENABLE, &off, 1);

	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_LE_CLEAR_RL, NULL, 0);
	if (err != 0) {
		return err;
	}
	for (uint8_t i = 0; i < key_count; i++) {
		uint8_t entry[KEY_ENTRY + 16u] = {0};

		memcpy(entry, keys[i], KEY_ENTRY);
		err = send_command(BT_HCI_OP_LE_ADD_DEV_TO_RL, entry,
				   sizeof(entry));
		if (err != 0) {
			return err;
		}
		uint8_t mode[8];

		memcpy(mode, keys[i], 7u);      /* type and identity address */
		mode[7] = 0x01u;                /* device privacy mode */
		err = send_command(BT_HCI_OP_LE_SET_PRIVACY_MODE, mode,
				   sizeof(mode));
		if (err != 0) {
			return err;
		}
	}
	return key_count > 0u
	       ? send_command(BT_HCI_OP_LE_SET_ADDR_RES_ENABLE, &on, 1)
	       : 0;
}
```

In `apply_filter()`, replace `int err = send_command(BT_HCI_OP_LE_CLEAR_FAL, NULL, 0);` with:

```c
	/* Keys first: the accept list may name identities that only the
	 * resolving list can recognise. */
	int err = apply_keys();

	if (err != 0) {
		return err;
	}
	err = send_command(BT_HCI_OP_LE_CLEAR_FAL, NULL, 0);
```

In `sn_radio_ble_stop()`, after `running = false;`:

```c
	/* Keys are secrets; they live for one capture. */
	memset(keys, 0, sizeof(keys));
	key_count = 0u;
```

`radio_ble.h`, after `sn_radio_ble_set_filter`:

```c
/* Identity resolving keys: N x 23 bytes, (identity type, identity address,
 * key), the last two least significant first. Refused whole if malformed or
 * more than CONFIG_BT_CTLR_RL_SIZE. Loaded at the next scan start, before
 * the accept list; cleared when the scan stops. */
int sn_radio_ble_set_keys(const uint8_t *payload, size_t len);
```

`control.c`, before the `SN_FRAME_BLE_FILTER` branch:

```c
	/* Keys ride in a frame for the same reason the filter does, and are
	 * likewise not answered. radio_ble.c logs a refusal. */
	if (type == (uint8_t)SN_FRAME_BLE_KEYS) {
		(void)sn_radio_ble_set_keys(payload, len);
		return;
	}
```

`main.c`: `#define SN_FIRMWARE_VERSION 5u`.

`prj.conf`, appended:

```
# Identity resolving keys: the controller's resolving list lets a scan report
# and filter a device that changes its address under its identity address.
# Both are defaults today; stated so a changed default cannot quietly take the
# feature away. The host reads the same size from boards.py "ble_keys".
CONFIG_BT_CTLR_PRIVACY=y
CONFIG_BT_CTLR_RL_SIZE=8
```

`host/src/esp32c6_sniffer/capture.py` (esp32c6-sniffer worktree): `"nrf54l15": 5,`.

- [ ] **Step 3: Build**

Run in pwsh: `& <scratchpad>\nrf_build.ps1 -Ncs G:\dev\tools\ncs -App G:\dev\projects\nrf54l15-sniffer-keys -Build G:\dev\scratch\nrf\bkeys`
Expected: `exit 0`.

- [ ] **Step 4: Run the host suite and commit in both repos**

Run: `$PYTEST -q` (esp32c6 worktree)
Expected: all pass.

```bash
cd /g/dev/projects/nrf54l15-sniffer-keys
git add shared src/radio_ble.c src/radio_ble.h src/control.c src/main.c prj.conf
git commit -m "feat: device keys go into the controller's resolving list (firmware 5)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
cd /g/dev/projects/esp32c6-sniffer-keys
git add host/src/esp32c6_sniffer/capture.py
git commit -m "feat: the host expects nRF54L15 firmware 5

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Documentation

**Files:**
- Modify: `README.md`: a new `#### Following a device that changes its address` at the end of `### Bluetooth LE` (which starts at about line 492), before `### Verifying the 11ax decoder`
- Modify: `nrf:README.md`: a short `## Device keys` section before `## Toolchain`

- [ ] **Step 1: Write the esp32c6-sniffer section**

It covers the following. Measured figures come in Task 13, so where a number is not yet measured, the sentence is left out rather than guessed.
1. **What it is for.** Phones and Macs change address every few minutes, and "Only these devices" loses them at the first change.
2. **The key file format**, with the example from the spec. Use `11:22:33:44:55:66` and `de:ad:be:ef:00:01` with the words "your device's key" instead of a real key. Hex is most significant first. Base64 is not described until Task 15.
3. **Getting a key from a Mac.**
   - Open Keychain Access, then Local Items, and search "Bluetooth".
   - Open the device's entry and choose *Show password*. It asks for your Mac login password.
   - The key is "Remote IRK".
   - The identity address: on an iPhone it is Settings → General → About → Bluetooth.
   - Only this route is described as tested.
4. **In Wireshark.** Choose the file under Device keys, type the identity into Only these devices, and start the capture. Check keys is on the interface toolbar (View → Interface Toolbars).
5. **What the three Check keys results mean, and the automatic backwards warning.**
6. **Capacity:** five keys on the ESP32-C6, eight on the nRF54L15. Four plain addresses, or up to eight identities, in the filter.
7. **Security.** The file is a secret. The keys go to the board's RAM for one capture and are cleared when it stops. They are never in the capture file. Keep the file out of repositories.
8. **The filter fix.** Before firmware 7/5, a typed random address filtered everything out.

- [ ] **Step 2: Write the nrf54l15-sniffer section**

It says:
- this firmware accepts `SN_FRAME_BLE_KEYS` from version 5 and holds 8 keys;
- the procedure lives in esp32c6-sniffer's README, "Following a device that changes its address";
- HCI command refusals are now reported, and a refused setup step fails START (Task 10).

- [ ] **Step 3: Run the guards, then commit in both repos**

Run: `$PYTEST tests/test_no_private_data.py tests/test_no_stray_control_characters.py -q`
Expected: pass.

```bash
cd /g/dev/projects/esp32c6-sniffer-keys && git add README.md && git commit -m "docs: following a BLE device that changes its address

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
cd /g/dev/projects/nrf54l15-sniffer-keys && git add README.md && git commit -m "docs: device keys and HCI command status

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: On the boards, both directions

**Files:**
- Throwaway: `<scratchpad>/keys_onair.py`, `<scratchpad>/keys.txt`, `<scratchpad>/keys_reversed.txt`, and the advertisers.
- Modify: `README.md` (the measured figures), committed at the end.

**Interfaces:**
- Consumes: everything above. The C6 capture build from Task 9 and `G:\dev\scratch\nrf\bkeys` from Task 11.

- [ ] **Step 1: Ask for the boards**

Message "Bluetooth exploration status" that COM3 and COM4 are needed for about an hour, and wait for its go-ahead.

- [ ] **Step 2: Rebuild the throwaway advertisers for the test identity**

Compute the three private addresses:

```bash
cd /g/dev/projects/esp32c6-sniffer-keys/host
PYTHONPATH=src /g/dev/projects/esp32c6-sniffer/host/.venv/Scripts/python.exe -c "
from esp32c6_sniffer.ble_keys import make_rpa
irk = bytes.fromhex('ec0234a357c8ad05341010a60a397d9b')
for p in (0x400001, 0x400002, 0x400003): print(make_rpa(irk, p))"
```

Then edit both advertisers:
- **XIAO:** `G:\dev\scratch\nrf\rpaadv\src\main.c`, the `rpas[3][6]` table, least significant byte first.
- **C6:** `<scratchpad>/c6vhciadv/main/app_bt.c`, its address table.

In both:
- use the three addresses above;
- add a fourth phase that advertises under the identity `de:ad:be:ef:00:01` itself (LE Set Random Address to it);
- rotate every 15 s: rpa1, rpa2, rpa3, identity.

Build and keep both. They are passive-test transmitters, outside both repos.

- [ ] **Step 3: Write the key files and the on-air script (throwaway)**

- `<scratchpad>/keys.txt` contains `de:ad:be:ef:00:01 random ec0234a357c8ad05341010a60a397d9b`.
- `<scratchpad>/keys_reversed.txt` holds the same key with its bytes reversed: `9b7d390aa610103405adc857a33402ec`.

`<scratchpad>/keys_onair.py`:

```python
"""On-air checks for device keys. usage:
keys_onair.py <port> <board> <seconds> <keys file|-> <filter|nofilter> [check]
Throwaway."""
import collections
import sys
import threading
import time

from esp32c6_sniffer.adv import parse_hci_advertising_reports
from esp32c6_sniffer.ble import hci_of_record
from esp32c6_sniffer.ble_keys import KeyCheck, filter_entries, parse_key_file
from esp32c6_sniffer.boards import board_by_id
from esp32c6_sniffer.capture import CaptureSession
from esp32c6_sniffer.control import Radio

port, board_id, seconds, key_path, mode = sys.argv[1:6]
do_check = len(sys.argv) > 6
keys = parse_key_file(key_path) if key_path != "-" else []
entries = filter_entries(["de:ad:be:ef:00:01"], keys) if mode == "filter" else []
counts = collections.Counter()
check = KeyCheck(keys)
done = threading.Event()
with CaptureSession(port, channel=0, radio=Radio.BLE, board=board_id,
                    baud=board_by_id(board_id)["baud"], ble_keys=keys,
                    ble_filter=entries) as session:
    end = time.monotonic() + float(seconds)
    if do_check:
        session.request_key_check(check.observe, done.set)
    for record, _, _ in session.records():
        for r in parse_hci_advertising_reports(hci_of_record(record)):
            counts[(r.address, r.address_type)] += 1
        if time.monotonic() >= end and (not do_check or done.is_set()):
            break
ours = {k: v for k, v in counts.items() if k[0] == "de:ad:be:ef:00:01"
        or k[1] == "resolvable private"}
print(f"{board_id} {seconds}s keys={key_path} {mode}: {sum(counts.values())} reports")
for (address, kind), n in sorted(ours.items(), key=lambda i: -i[1])[:10]:
    print(f"  {address}  {kind:20s} {n}")
print(f"  others: {sum(counts.values()) - sum(ours.values())}")
if do_check:
    for result in check.results():
        print("  check:", result.message("keys"))
```

It prints private addresses, which are fine in a scratch terminal. Do not paste any of them into the repo.

- [ ] **Step 4: Direction A: the C6 sniffer, the XIAO advertiser**

Flash the XIAO with the advertiser and the C6 with the Task 9 capture build:

```powershell
pwsh -File G:\dev\projects\esp32c6-sniffer-keys\firmware\flash.ps1 -Port COM3
```

Then run each of these from the worktree's `host/` with `PYTHONPATH=src`, recording the output:

| Run | Expect |
|---|---|
| `keys_onair.py COM3 esp32c6 60 keys.txt nofilter` | Only `de:ad:be:ef:00:01` for our advertiser, as `random identity` during the RPA phases. During the identity phase, whatever type the controller reports (record which). No resolvable private address from it. |
| `keys_onair.py COM3 esp32c6 60 keys.txt filter` | Reports from the identity throughout all four phases; others 0. This is step 4 (device privacy mode) working. |
| `keys_onair.py COM3 esp32c6 60 keys_reversed.txt nofilter` | The advertiser's private addresses arrive unresolved. |
| extcap: the same, with `--ble-keys keys_reversed.txt` | A pop-up/log/comment on line 1 (check the pcapng with `tshark -r out.pcapng -Y pkt_comment`). |
| `keys_onair.py COM3 esp32c6 30 keys.txt filter check` | Check result for line 1: `correct`. |
| `keys_onair.py COM3 esp32c6 30 keys_reversed.txt filter check` | `BACKWARDS`. |
| The same with the advertiser unplugged | `nothing matched`. |
| `keys_onair.py COM3 esp32c6 20 - filter`, then `... 20 - nofilter` | The second run hears other advertisers (the stale-filter fix; matters most on the nRF). |

For the extcap run, use `python extcap/esp32c6-sniffer.py --capture --extcap-interface esp32c6-ble --fifo <scratch>/out.pcapng --ble-keys <scratch>/keys_reversed.txt`, stopped after 60 s with `Popen.terminate()`.

**Capacity:** write a five-line and a six-line key file (identities `de:ad:be:ef:00:0N`). Five loads with no refusal in the log, and six is refused by the host before anything is sent.

**Privacy mode is needed** (the spec's step 4 check), on this board:
- Build a throwaway copy of the Task 9 firmware in the scratchpad with the `OPCODE_LE_SET_PRIVACY_MODE` call removed.
- Flash it and run the filtered 60 s capture. Expected: no reports during the identity phase.
- Reflash the Task 9 build afterwards.

**Wireshark decodes the identity:**
- Check the field names first: `tshark -G fields | findstr /C:"le_peer_address_type"` gives the real field name for the address type.
- Then `tshark -r out.pcapng -T fields -e <that field> | sort | uniq -c` shows the random identity type.

- [ ] **Step 5: Direction B: the XIAO sniffer, the C6 advertiser**

Flash the C6 with the rebuilt `c6vhciadv` and the XIAO with `G:\dev\scratch\nrf\bkeys` (`nrf_flash_verify.ps1 -Build G:\dev\scratch\nrf\bkeys`, expected `verified`).

Repeat the Step 4 table with `COM4 nrf54l15`. Capacity here is eight loads and nine refused (the host refuses nine at parse time, `MAX_DEVICE_KEYS`).

The **stale-filter** row matters most here. Run `<scratchpad>/filter_type_check.py COM4 nrf54l15 20` twice with the worktree host. The second run's unfiltered line must show many addresses; Task 10 Step 2 recorded what it showed before.

Also build and run the **privacy-mode-removed** throwaway nRF copy.

**Periodic following still works after Task 10, and Check keys' cost to it:**
- Flash the C6 with ESP-IDF's unmodified `periodic_adv` example (`<scratchpad>/c6rpaadv` was a copy of it; rebuild from `$IDF_PATH/examples/bluetooth/bluedroid/ble_50/periodic_adv`).
- Capture on the XIAO with `ble_periodic=True` for 30 s. Expected: the `periodic synced` counter above 0 and periodic reports arriving. This is the check that the sync worker still works on `hci_command()`.
- Then press Check keys (`request_key_check`) mid-capture and record how long the train takes to come back.

- [ ] **Step 6: Restore both boards and hand them back**

- Flash C6 firmware 7 and XIAO firmware 5 (the capture builds).
- Check with `BoardLink` from the worktree host: expected `esp32c6 firmware 7` and `nrf54l15 firmware 5`.
- Message the other session: boards free. Both now run the new firmware (7 and 5), which the host on `main` refuses until this branch merges; its own captures need this branch's host, or a reflash to its builds.

- [ ] **Step 7: Record the measurements**

Add to the README section from Task 12 what was measured, with dates, the way `docs/` notes elsewhere record figures:
- the report counts;
- the identity-phase behaviour and its reported type;
- the privacy-mode comparison;
- the capacity;
- the periodic re-sync time.

Do not paste any private address. Run the private-data guard, then commit:

```bash
git add README.md && git commit -m "docs: device keys measured on both boards

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 14: Merge locally

**Files:** none new.

- [ ] **Step 1: Full suite in the worktree**

Run: `$PYTEST -q`
Expected: all pass.

- [ ] **Step 2: Merge shared, then the two repos, into their main branches (no push)**

```bash
git -C /g/dev/projects/esp32c6-sniffer/shared fetch /g/dev/projects/esp32c6-sniffer-keys/shared ble-keys-frame
git -C /g/dev/projects/esp32c6-sniffer/shared merge --ff-only FETCH_HEAD
git -C /g/dev/projects/esp32c6-sniffer pull --ff-only
git -C /g/dev/projects/esp32c6-sniffer merge --no-ff ble-device-keys -m "Merge: BLE device keys

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git -C /g/dev/projects/nrf54l15-sniffer pull --ff-only
git -C /g/dev/projects/nrf54l15-sniffer merge --no-ff ble-device-keys -m "Merge: BLE device keys

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git -C /g/dev/projects/nrf54l15-sniffer submodule update
```

- If the esp32c6-sniffer merge conflicts in `capture.py` (the other session changed STATS parsing there), keep both sides' changes.
- Run the full suite on `main` afterwards: `cd /g/dev/projects/esp32c6-sniffer/host && .venv/Scripts/python.exe -m pytest -q`.
- **When the user asks to push, push `sniffer-wire-format` (shared) first.** Both repos' submodule pointers name its commit, and CI checks it out.

- [ ] **Step 3: Tell the other session**

Message: "BLE device keys are merged into main locally (not pushed). The host now expects C6 firmware 7 and nRF firmware 5, and both boards run those."

---

### Task 15: With the user: the Wireshark button, and the Keychain byte order

**Files:**
- Modify: `host/src/esp32c6_sniffer/ble_keys.py` (`KEYCHAIN_BASE64_REVERSED`)
- Modify: `host/tests/test_ble_keys.py`
- Modify: `README.md`

- [ ] **Step 1: The user presses Check keys in the Wireshark window**

The dev install runs the main checkout's extcap, so the merged code is live. Ask the user to:
- start a BLE capture with Device keys set to a key file;
- open View → Interface Toolbars → the sniffer's toolbar;
- press Check keys.

Expected: a pop-up after about 20 s, and the log lines.

- [ ] **Step 2: The user extracts a Mac key, and the check settles its order**

Ask the user to:
- copy the "Remote IRK" base64 from Keychain Access (they type the login password; never enter it for them);
- put it in a key file with the identity address and `public`;
- capture with that device nearby and press Check keys.

They may report only the one-line result.

- **"correct":** leave `KEYCHAIN_BASE64_REVERSED = False`.
- **"BACKWARDS":** set it to `True`.

Either way, pin it with a test:

```python
def test_keychain_base64_order_is_the_measured_one():
    """Measured 2026-09-DD on the user's Mac: Keychain's Remote IRK is
    <most|least> significant byte first."""
    assert KEYCHAIN_BASE64_REVERSED is <True|False>
```

Fill in the measured date and order when this step runs. These are the measurement's results, not plan placeholders.

- [ ] **Step 3: Document base64 in the README section and the tooltip, then commit on main**

```bash
git -C /g/dev/projects/esp32c6-sniffer add host/src/esp32c6_sniffer/ble_keys.py host/tests/test_ble_keys.py README.md extcap/esp32c6-sniffer.py
git -C /g/dev/projects/esp32c6-sniffer commit -m "feat: macOS Keychain keys read in their measured byte order

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 4: Remove the worktrees**

```bash
git -C /g/dev/projects/esp32c6-sniffer worktree remove /g/dev/projects/esp32c6-sniffer-keys
git -C /g/dev/projects/nrf54l15-sniffer worktree remove /g/dev/projects/nrf54l15-sniffer-keys
```
