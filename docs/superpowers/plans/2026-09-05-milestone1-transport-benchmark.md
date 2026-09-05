# Milestone 1: USB Transport and Throughput Benchmark — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the framed USB transport between an ESP32-C6 and a PC, then measure its actual sustained throughput — a figure that has never been published for this chip.

**Architecture:** A pure-C frame codec on the firmware and a mirror implementation in Python, proven byte-identical against shared golden vectors. Frames are composed into a FreeRTOS ring buffer and drained to USB-Serial-JTAG in bulk writes, never through stdio. The host parser resynchronises after data loss, because the transport silently discards bytes when the host stops reading.

**Tech Stack:** ESP-IDF v6.1 (C), Python 3.10+ with pytest and pyserial, Seeed XIAO ESP32-C6 on COM3.

## Global Constraints

Copied from the spec. Every task's requirements implicitly include these.

- **ESP-IDF v6.1**, pinned to the `v6.1` **tag**, not `release/v6.1` (the branch has moved past the tag and is not reproducible).
- **Target chip:** `esp32c6`. Board: Seeed XIAO ESP32-C6, ESP32-C6FH4, 4 MB embedded flash, **no PSRAM**, 512 KB SRAM.
- **Serial port:** `COM3`. USB VID `303A`, PID `1001`.
- **`CONFIG_ESP_CONSOLE_SECONDARY_NONE=y` is mandatory.** The ESP-IDF default routes console output to USB-Serial-JTAG *as a secondary channel even when the primary console is a UART*. Leaving it default injects log text into the capture stream.
- **Never write frame data through stdio** (`printf`, `fwrite`, `puts`). The VFS path is byte-at-a-time and applies CRLF translation, inserting `0x0D` before every `0x0A` byte in binary payloads. Use `usb_serial_jtag_write_bytes()` only.
- **GPIO3 must be driven LOW** at startup, unconditionally, before any radio is enabled. It powers the board's RF switch, which is unpowered at reset.
- **GPIO14** selects the antenna: `0` = onboard ceramic, `1` = external U.FL. Hold both pins, never pulse.
- **Power management must be disabled.** Light sleep gates the USB PHY clock and kills the link.
- **Passive only.** No transmit, no injection. Milestone 1 touches no radio at all.
- **Python 3.10+** (ESP-IDF v6.1 floor). Host tooling runs in a project venv, not system Python.
- CRC is **CRC-16/CCITT-FALSE**: polynomial `0x1021`, init `0xFFFF`, no reflection, no final XOR. Check value for `b"123456789"` is `0x29B1`.

---

## File Structure

```
firmware/
  CMakeLists.txt              project root
  sdkconfig.defaults          all mandatory config from Global Constraints
  main/
    CMakeLists.txt
    main.c                    entry point, wires modules together
    board.h / board.c         RF switch + antenna select GPIO
    frame.h / frame.c         pure-C frame codec (no ESP dependencies)
    usb_link.h / usb_link.c   ring buffer, bulk writer, TX health watchdog
    log_sink.h / log_sink.c   esp_log hook emitting LOG frames
    bench.h / bench.c         synthetic frame generator for throughput test

host/
  pyproject.toml
  src/esp32c6_sniffer/
    __init__.py
    framing.py                CRC + frame encode/decode (mirror of frame.c)
    parser.py                 streaming parser with resync
    link.py                   serial transport with large RX buffer
    benchmark.py              throughput measurement CLI
  tests/
    test_framing.py
    test_parser.py
    vectors/golden.json       shared conformance vectors
```

**Why `frame.c` has no ESP dependencies:** it must produce bytes identical to `framing.py`. Keeping it dependency-free means the conformance test compares real firmware output against real Python output, with no mocking on either side.

---

### Task 1: Host frame codec

**Files:**
- Create: `host/pyproject.toml`
- Create: `host/src/esp32c6_sniffer/__init__.py`
- Create: `host/src/esp32c6_sniffer/framing.py`
- Test: `host/tests/test_framing.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `crc16_ccitt_false(data: bytes, crc: int = 0xFFFF) -> int`; `FrameType` IntEnum with members `PACKET=1, LOG=2, STATS=3, HEARTBEAT=4, CONTROL_REPLY=5`; `Frame` dataclass with fields `ftype: FrameType, seq: int, payload: bytes, flags: int`; `encode_frame(ftype: FrameType, seq: int, payload: bytes, flags: int = 0) -> bytes`; `decode_frame(buf: bytes) -> Frame` (raises `FrameError`); constants `MAGIC = 0x5AC6`, `HEADER_LEN = 10`, `MAX_PAYLOAD = 4096`; exception `FrameError`.

**Wire format** (little-endian throughout, header is 10 bytes):

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 2 | magic | `0x5AC6` |
| 2 | 1 | type | see `FrameType` |
| 3 | 1 | flags | reserved, 0 |
| 4 | 2 | seq | wraps at 65536 |
| 6 | 2 | length | payload bytes, `<= MAX_PAYLOAD` |
| 8 | 2 | hdr_crc | CRC-16/CCITT-FALSE over bytes 0..7 |
| 10 | N | payload | |

The CRC covers the header only. Payload integrity is already provided by the radio FCS and by USB's own per-packet CRC, and a payload CRC would cost real CPU on a chip with no CRC peripheral.

- [ ] **Step 1: Create the host package skeleton**

`host/pyproject.toml`:

```toml
[project]
name = "esp32c6-sniffer"
version = "0.1.0"
requires-python = ">=3.10"
dependencies = ["pyserial>=3.5"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

`host/src/esp32c6_sniffer/__init__.py`:

```python
"""Host tooling for the ESP32-C6 passive sniffer."""

__version__ = "0.1.0"
```

- [ ] **Step 2: Write the failing tests**

`host/tests/test_framing.py`:

```python
import pytest

from esp32c6_sniffer.framing import (
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    FrameError,
    FrameType,
    crc16_ccitt_false,
    decode_frame,
    encode_frame,
)


def test_crc_matches_published_check_value():
    # CRC-16/CCITT-FALSE check value, from the CRC catalogue.
    assert crc16_ccitt_false(b"123456789") == 0x29B1


def test_crc_of_empty_input_is_init_value():
    assert crc16_ccitt_false(b"") == 0xFFFF


def test_encoded_header_is_ten_bytes():
    frame = encode_frame(FrameType.HEARTBEAT, seq=0, payload=b"")
    assert len(frame) == HEADER_LEN


def test_encoded_frame_starts_with_magic():
    frame = encode_frame(FrameType.PACKET, seq=1, payload=b"xy")
    assert int.from_bytes(frame[0:2], "little") == MAGIC


def test_round_trip_preserves_all_fields():
    payload = bytes(range(200))
    frame = encode_frame(FrameType.PACKET, seq=1234, payload=payload, flags=0)
    decoded = decode_frame(frame)
    assert decoded.ftype is FrameType.PACKET
    assert decoded.seq == 1234
    assert decoded.payload == payload
    assert decoded.flags == 0


def test_sequence_number_wraps_at_16_bits():
    frame = encode_frame(FrameType.PACKET, seq=65536 + 7, payload=b"")
    assert decode_frame(frame).seq == 7


def test_payload_containing_newline_bytes_survives_intact():
    # Guards the stdio CRLF-translation corruption the spec warns about.
    payload = b"\x0a\x0d\x0a\x0a\x00\xff\x0a"
    frame = encode_frame(FrameType.PACKET, seq=0, payload=payload)
    assert decode_frame(frame).payload == payload


def test_oversized_payload_is_rejected():
    with pytest.raises(FrameError):
        encode_frame(FrameType.PACKET, seq=0, payload=b"\x00" * (MAX_PAYLOAD + 1))


def test_corrupted_header_is_rejected():
    frame = bytearray(encode_frame(FrameType.PACKET, seq=5, payload=b"abc"))
    frame[4] ^= 0xFF  # flip a bit in the sequence number
    with pytest.raises(FrameError):
        decode_frame(bytes(frame))


def test_bad_magic_is_rejected():
    frame = bytearray(encode_frame(FrameType.PACKET, seq=5, payload=b"abc"))
    frame[0] ^= 0xFF
    with pytest.raises(FrameError):
        decode_frame(bytes(frame))


def test_truncated_frame_is_rejected():
    frame = encode_frame(FrameType.PACKET, seq=5, payload=b"abcdef")
    with pytest.raises(FrameError):
        decode_frame(frame[:-2])
```

- [ ] **Step 3: Run the tests and confirm they fail**

```bash
cd host
py -m venv .venv
./.venv/Scripts/python.exe -m pip install -q -e ".[dev]"
./.venv/Scripts/python.exe -m pytest tests/test_framing.py -q
```

Expected: collection error, `ModuleNotFoundError: No module named 'esp32c6_sniffer.framing'`.

- [ ] **Step 4: Implement the codec**

`host/src/esp32c6_sniffer/framing.py`:

```python
"""Wire framing for the ESP32-C6 sniffer link.

This is the authoritative definition. `firmware/main/frame.c` mirrors it and is
held to byte-identical output by the golden vectors in tests/vectors/golden.json.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

MAGIC = 0x5AC6
HEADER_LEN = 10
MAX_PAYLOAD = 4096

_HEADER_STRUCT = struct.Struct("<HBBHH")  # magic, type, flags, seq, length


class FrameError(Exception):
    """Raised when bytes do not form a valid frame."""


class FrameType(IntEnum):
    PACKET = 1
    LOG = 2
    STATS = 3
    HEARTBEAT = 4
    CONTROL_REPLY = 5


@dataclass(frozen=True)
class Frame:
    ftype: FrameType
    seq: int
    payload: bytes
    flags: int = 0


def crc16_ccitt_false(data: bytes, crc: int = 0xFFFF) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final XOR."""
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def encode_frame(
    ftype: FrameType, seq: int, payload: bytes, flags: int = 0
) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise FrameError(f"payload {len(payload)} exceeds MAX_PAYLOAD {MAX_PAYLOAD}")
    header = _HEADER_STRUCT.pack(
        MAGIC, int(ftype), flags & 0xFF, seq & 0xFFFF, len(payload)
    )
    return header + struct.pack("<H", crc16_ccitt_false(header)) + payload


def decode_frame(buf: bytes) -> Frame:
    """Decode exactly one frame from the start of `buf`. Raises FrameError."""
    if len(buf) < HEADER_LEN:
        raise FrameError("buffer shorter than header")
    magic, ftype, flags, seq, length = _HEADER_STRUCT.unpack(buf[:8])
    if magic != MAGIC:
        raise FrameError(f"bad magic {magic:#06x}")
    expected_crc = struct.unpack("<H", buf[8:10])[0]
    if crc16_ccitt_false(buf[:8]) != expected_crc:
        raise FrameError("header CRC mismatch")
    if length > MAX_PAYLOAD:
        raise FrameError(f"length {length} exceeds MAX_PAYLOAD")
    if len(buf) < HEADER_LEN + length:
        raise FrameError("buffer shorter than declared payload")
    try:
        ftype_enum = FrameType(ftype)
    except ValueError as exc:
        raise FrameError(f"unknown frame type {ftype}") from exc
    return Frame(
        ftype=ftype_enum,
        seq=seq,
        payload=buf[HEADER_LEN : HEADER_LEN + length],
        flags=flags,
    )
```

- [ ] **Step 5: Run the tests and confirm they pass**

```bash
cd host && ./.venv/Scripts/python.exe -m pytest tests/test_framing.py -q
```

Expected: `11 passed`.

- [ ] **Step 6: Commit**

```bash
git add host/pyproject.toml host/src host/tests
git commit -m "feat(host): frame codec with CRC-16/CCITT-FALSE header check"
```

---

### Task 2: Streaming parser with resynchronisation

**Files:**
- Create: `host/src/esp32c6_sniffer/parser.py`
- Test: `host/tests/test_parser.py`

**Interfaces:**
- Consumes: from `framing.py` — `Frame`, `FrameType`, `FrameError`, `decode_frame`, `encode_frame`, `HEADER_LEN`, `MAGIC`, `MAX_PAYLOAD`.
- Produces: `StreamParser` class with `feed(data: bytes) -> list[Frame]` and `force_resync() -> list[Frame]`, plus read-only attributes `resync_count: int`, `bytes_discarded: int`, `frames_parsed: int`. Also `SequenceTracker` with `observe(seq: int) -> int` returning the number of frames missed before this one, and attribute `total_missed: int`.

**A note on the deadlock `force_resync` exists to break.** The header CRC covers
the header only, so a frame whose payload is truncated by data loss still
presents a *valid* header declaring a length that will never arrive. The parser
cannot tell that from a payload still in flight, and must not guess — guessing
would splice the next frame's bytes into this one's payload and emit a corrupt
frame. Only the caller knows it has waited too long, so the caller breaks the
stall. Task 7's benchmark and, later, the extcap reader must call this on a read
timeout.

**Why this exists:** the firmware discards bytes when the host stops reading, so the stream can lose an arbitrary run mid-frame. The parser must find the next real frame rather than misparsing, and must report how much it threw away.

- [ ] **Step 1: Write the failing tests**

`host/tests/test_parser.py`:

```python
from esp32c6_sniffer.framing import FrameType, encode_frame
from esp32c6_sniffer.parser import SequenceTracker, StreamParser


def test_single_whole_frame_is_parsed():
    parser = StreamParser()
    frames = parser.feed(encode_frame(FrameType.PACKET, 1, b"hello"))
    assert len(frames) == 1
    assert frames[0].payload == b"hello"


def test_two_frames_in_one_chunk():
    parser = StreamParser()
    data = encode_frame(FrameType.PACKET, 1, b"aa") + encode_frame(
        FrameType.PACKET, 2, b"bb"
    )
    frames = parser.feed(data)
    assert [f.payload for f in frames] == [b"aa", b"bb"]


def test_frame_split_across_many_feeds():
    parser = StreamParser()
    data = encode_frame(FrameType.PACKET, 7, bytes(range(100)))
    collected = []
    for i in range(0, len(data), 3):
        collected.extend(parser.feed(data[i : i + 3]))
    assert len(collected) == 1
    assert collected[0].seq == 7


def test_leading_garbage_is_discarded_and_counted():
    parser = StreamParser()
    data = b"\x11\x22\x33\x44" + encode_frame(FrameType.PACKET, 1, b"ok")
    frames = parser.feed(data)
    assert len(frames) == 1
    assert frames[0].payload == b"ok"
    assert parser.bytes_discarded == 4
    assert parser.resync_count == 1


def test_truncated_frame_stalls_until_forced_resync():
    """A valid header whose payload was lost is indistinguishable from one
    still in flight. The parser must wait, and only the caller — which knows
    it has timed out — can break the deadlock."""
    good = encode_frame(FrameType.PACKET, 1, b"first")
    truncated = encode_frame(FrameType.PACKET, 2, b"X" * 50)[:20]
    following = encode_frame(FrameType.PACKET, 3, b"third")

    parser = StreamParser()
    first_batch = parser.feed(good + truncated + following)
    assert [f.payload for f in first_batch] == [b"first"], (
        "parser must not guess past an incomplete payload"
    )

    recovered = parser.force_resync()
    assert [f.payload for f in recovered] == [b"third"]
    assert parser.resync_count >= 1


def test_false_magic_inside_payload_does_not_desynchronise():
    # A payload containing the magic bytes must not be mistaken for a header.
    payload = b"\xc6\x5a\x01\x00\x00\x00\x10\x00" * 4
    parser = StreamParser()
    frames = parser.feed(encode_frame(FrameType.PACKET, 1, payload))
    assert len(frames) == 1
    assert frames[0].payload == payload


def test_sequence_tracker_reports_no_loss_when_contiguous():
    tracker = SequenceTracker()
    for seq in range(5):
        assert tracker.observe(seq) == 0
    assert tracker.total_missed == 0


def test_sequence_tracker_counts_a_gap():
    tracker = SequenceTracker()
    tracker.observe(10)
    assert tracker.observe(14) == 3
    assert tracker.total_missed == 3


def test_sequence_tracker_handles_wraparound():
    tracker = SequenceTracker()
    tracker.observe(65534)
    assert tracker.observe(1) == 2
    assert tracker.total_missed == 2
```

- [ ] **Step 2: Run the tests and confirm they fail**

```bash
cd host && ./.venv/Scripts/python.exe -m pytest tests/test_parser.py -q
```

Expected: `ModuleNotFoundError: No module named 'esp32c6_sniffer.parser'`.

- [ ] **Step 3: Implement the parser**

`host/src/esp32c6_sniffer/parser.py`:

```python
"""Streaming frame parser that recovers from mid-stream data loss."""

from __future__ import annotations

import struct

from .framing import (
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    Frame,
    FrameError,
    decode_frame,
)

_MAGIC_BYTES = struct.pack("<H", MAGIC)


class StreamParser:
    """Accumulates bytes and yields whole frames, resynchronising after loss."""

    def __init__(self) -> None:
        self._buf = bytearray()
        self.resync_count = 0
        self.bytes_discarded = 0
        self.frames_parsed = 0

    def feed(self, data: bytes) -> list[Frame]:
        self._buf.extend(data)
        frames: list[Frame] = []
        while True:
            frame = self._try_one()
            if frame is None:
                return frames
            frames.append(frame)

    def force_resync(self) -> list[Frame]:
        """Abandon a partially received frame and hunt for the next one.

        The header CRC covers only the header, so a frame truncated by data
        loss still presents a valid header declaring a length that will never
        arrive. That is indistinguishable from a payload still in flight, so
        the parser waits. Only the caller knows it has timed out. Call this
        on a read timeout to break the stall.
        """
        if self._buf:
            self._discard_one_byte_and_resync()
        return self.feed(b"")

    def _try_one(self) -> Frame | None:
        while True:
            if len(self._buf) < HEADER_LEN:
                return None
            try:
                frame = decode_frame(bytes(self._buf))
            except FrameError:
                # Either not a frame start, or the payload has not arrived yet.
                # Distinguish: a valid header with a short payload must wait.
                if self._header_is_valid_but_incomplete():
                    return None
                self._discard_one_byte_and_resync()
                continue
            del self._buf[: HEADER_LEN + len(frame.payload)]
            self.frames_parsed += 1
            return frame

    def _header_is_valid_but_incomplete(self) -> bool:
        from .framing import crc16_ccitt_false

        head = bytes(self._buf[:8])
        if head[:2] != _MAGIC_BYTES:
            return False
        if crc16_ccitt_false(head) != struct.unpack("<H", self._buf[8:10])[0]:
            return False
        length = struct.unpack("<H", head[6:8])[0]
        if length > MAX_PAYLOAD:
            return False
        return len(self._buf) < HEADER_LEN + length

    def _discard_one_byte_and_resync(self) -> None:
        """Drop the leading byte, then jump to the next plausible magic."""
        del self._buf[0]
        self.bytes_discarded += 1
        idx = self._buf.find(_MAGIC_BYTES)
        if idx > 0:
            self.bytes_discarded += idx
            del self._buf[:idx]
        elif idx == -1:
            # Keep only a possible split magic byte at the tail.
            keep = 1 if self._buf[-1:] == _MAGIC_BYTES[:1] else 0
            drop = len(self._buf) - keep
            if drop > 0:
                self.bytes_discarded += drop
                del self._buf[:drop]
        self.resync_count += 1


class SequenceTracker:
    """Counts frames missing between consecutive sequence numbers."""

    def __init__(self) -> None:
        self._last: int | None = None
        self.total_missed = 0

    def observe(self, seq: int) -> int:
        if self._last is None:
            self._last = seq
            return 0
        missed = (seq - self._last - 1) % 65536
        self._last = seq
        self.total_missed += missed
        return missed
```

Note the resync counter increments once per recovery attempt, so a single
long garbage run may register more than one. The tests assert `>= 1`, not equality.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
cd host && ./.venv/Scripts/python.exe -m pytest tests/ -q
```

Expected: `20 passed`.

- [ ] **Step 5: Commit**

```bash
git add host/src/esp32c6_sniffer/parser.py host/tests/test_parser.py
git commit -m "feat(host): streaming parser with resync and sequence gap tracking"
```

---

### Task 3: Firmware scaffold and board bring-up

**Files:**
- Create: `firmware/CMakeLists.txt`
- Create: `firmware/sdkconfig.defaults`
- Create: `firmware/main/CMakeLists.txt`
- Create: `firmware/main/board.h`
- Create: `firmware/main/board.c`
- Create: `firmware/main/main.c`

**Interfaces:**
- Consumes: nothing.
- Produces: `typedef enum { SN_ANTENNA_INTERNAL = 0, SN_ANTENNA_EXTERNAL = 1 } sn_antenna_t;` and `esp_err_t sn_board_init(sn_antenna_t antenna);` from `board.h`.

**Prerequisite:** ESP-IDF v6.1 installed and the export script run in the shell.

- [ ] **Step 1: Write the project files**

`firmware/CMakeLists.txt`:

```cmake
cmake_minimum_required(VERSION 3.22.1)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32c6_sniffer)
```

`firmware/sdkconfig.defaults` — every line here is load-bearing, see Global Constraints:

```
CONFIG_IDF_TARGET="esp32c6"
CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y

# Console on UART0 (GPIO16, header pin D6). The SECONDARY setting is critical:
# the ESP-IDF default also mirrors console output onto USB-Serial-JTAG, which
# would inject log text into the framed data stream.
CONFIG_ESP_CONSOLE_UART_DEFAULT=y
CONFIG_ESP_CONSOLE_SECONDARY_NONE=y

# Light sleep gates the USB PHY clock and kills the link.
CONFIG_PM_ENABLE=n

CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ_160=y
CONFIG_COMPILER_OPTIMIZATION_PERF=y
CONFIG_FREERTOS_HZ=1000
```

`firmware/main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c" "board.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio
)
```

`firmware/main/board.h`:

```c
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Seeed XIAO ESP32-C6 RF path.
 *
 * GPIO3  drives the gate of a P-FET supplying the FM8625H RF switch.
 *        It is pulled up at reset, so the switch is UNPOWERED on boot and the
 *        radio reaches its antenna only through roughly 30 dB of leakage.
 *        Driving it LOW powers the switch. This is not optional.
 * GPIO14 is the switch's VCTL: 0 selects the onboard ceramic antenna (RF1),
 *        1 selects the external U.FL connector (RF2).
 *
 * Both pins are internal-only and must be HELD, not pulsed.
 */
#define SN_PIN_RF_SWITCH_PWR 3
#define SN_PIN_ANTENNA_SEL   14

typedef enum {
    SN_ANTENNA_INTERNAL = 0,
    SN_ANTENNA_EXTERNAL = 1,
} sn_antenna_t;

/* Powers the RF switch and selects an antenna.
 * Must be called before enabling any radio. */
esp_err_t sn_board_init(sn_antenna_t antenna);

#ifdef __cplusplus
}
#endif
```

`firmware/main/board.c`:

```c
#include "board.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "board";

esp_err_t sn_board_init(sn_antenna_t antenna)
{
    const gpio_config_t io = {
        .pin_bit_mask = (1ULL << SN_PIN_RF_SWITCH_PWR) |
                        (1ULL << SN_PIN_ANTENNA_SEL),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&io);
    if (err != ESP_OK) {
        return err;
    }

    /* Power the RF switch. LOW = on. Always, for either antenna. */
    err = gpio_set_level(SN_PIN_RF_SWITCH_PWR, 0);
    if (err != ESP_OK) {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(100));

    err = gpio_set_level(SN_PIN_ANTENNA_SEL, antenna == SN_ANTENNA_EXTERNAL ? 1 : 0);
    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGI(TAG, "RF switch powered, antenna=%s",
             antenna == SN_ANTENNA_EXTERNAL ? "external" : "internal");
    return ESP_OK;
}
```

`firmware/main/main.c`:

```c
#include "board.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

void app_main(void)
{
    ESP_ERROR_CHECK(sn_board_init(SN_ANTENNA_INTERNAL));
    ESP_LOGI(TAG, "milestone 1 scaffold up");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

- [ ] **Step 2: Build**

```bash
cd firmware
idf.py set-target esp32c6
idf.py build
```

Expected: `Project build complete.` If the build fails on warnings, note that
v6 makes compiler warnings errors by default; fix the warning rather than
disabling the setting.

- [ ] **Step 3: Verify the mandatory config actually landed**

Silent misconfiguration here corrupts every later capture, so assert it rather than assume it.

```bash
cd firmware
grep -E "CONFIG_ESP_CONSOLE_SECONDARY_NONE|CONFIG_ESP_CONSOLE_UART_DEFAULT|CONFIG_PM_ENABLE" sdkconfig
```

Expected exactly:

```
CONFIG_ESP_CONSOLE_UART_DEFAULT=y
CONFIG_ESP_CONSOLE_SECONDARY_NONE=y
# CONFIG_PM_ENABLE is not set
```

If `CONFIG_ESP_CONSOLE_SECONDARY_USB_SERIAL_JTAG=y` appears instead, stop and fix it before continuing.

- [ ] **Step 4: Flash and confirm USB stays silent**

```bash
cd firmware
idf.py -p COM3 flash
```

Then confirm nothing arrives on the USB CDC port, because the console is on UART:

```bash
cd host
./.venv/Scripts/python.exe -c "
import serial, time
s = serial.Serial('COM3', 115200, timeout=0.2)
end = time.monotonic() + 3
n = 0
while time.monotonic() < end:
    n += len(s.read(4096))
s.close()
print('bytes on USB CDC:', n)
"
```

Expected: `bytes on USB CDC: 0`. Any non-zero value means console output is
leaking onto the data path, which would corrupt captures. Fix before continuing.

If flashing fails, hold BOOT, tap RESET, release BOOT, and retry.

- [ ] **Step 5: Commit**

```bash
git add firmware/
git commit -m "feat(fw): project scaffold, board RF switch bring-up, console off USB"
```

---

### Task 4: Firmware frame codec, proven byte-identical to the host

**Files:**
- Create: `firmware/main/frame.h`
- Create: `firmware/main/frame.c`
- Modify: `firmware/main/CMakeLists.txt` (add `frame.c`)
- Modify: `firmware/main/main.c` (emit conformance vectors once at boot)
- Create: `host/tests/vectors/golden.json`
- Create: `host/tests/test_conformance.py`

**Interfaces:**
- Consumes: `sn_board_init` from Task 3; `encode_frame`, `FrameType`, `StreamParser` from Tasks 1–2.
- Produces: `sn_frame_type_t` enum matching `FrameType`; `#define SN_HEADER_LEN 10`; `#define SN_MAX_PAYLOAD 4096`; `uint16_t sn_crc16(const uint8_t *data, size_t len);` and `size_t sn_frame_encode(uint8_t *out, size_t out_cap, sn_frame_type_t type, uint16_t seq, const uint8_t *payload, size_t payload_len);` returning bytes written or 0 on failure.

- [ ] **Step 1: Generate the golden vectors from the host implementation**

```bash
cd host
./.venv/Scripts/python.exe -c "
import json, pathlib
from esp32c6_sniffer.framing import FrameType, encode_frame
cases = [
    ('empty_heartbeat', FrameType.HEARTBEAT, 0, b''),
    ('short_packet', FrameType.PACKET, 1, b'hello'),
    ('newline_bytes', FrameType.PACKET, 2, bytes([0x0a,0x0d,0x0a,0x00,0xff])),
    ('all_byte_values', FrameType.PACKET, 3, bytes(range(256))),
    ('seq_wrap', FrameType.PACKET, 65535, b'wrap'),
    ('log_frame', FrameType.LOG, 42, b'I (123) tag: msg'),
]
out = [{'name': n, 'type': int(t), 'seq': s, 'payload': p.hex(),
        'encoded': encode_frame(t, s, p).hex()} for n, t, s, p in cases]
pathlib.Path('tests/vectors').mkdir(parents=True, exist_ok=True)
pathlib.Path('tests/vectors/golden.json').write_text(json.dumps(out, indent=2))
print('wrote', len(out), 'vectors')
"
```

Expected: `wrote 6 vectors`.

- [ ] **Step 2: Write the failing conformance test**

`host/tests/test_conformance.py`:

```python
"""Holds firmware frame.c to byte-identical output with framing.py.

Run with hardware attached:  pytest -m hardware --port COM3
"""

import json
import pathlib

import pytest

from esp32c6_sniffer.framing import FrameType, encode_frame

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "golden.json").read_text()
)


@pytest.mark.parametrize("case", VECTORS, ids=lambda c: c["name"])
def test_host_encoder_still_matches_stored_vectors(case):
    """Guards against an accidental wire-format change on the host side."""
    produced = encode_frame(
        FrameType(case["type"]), case["seq"], bytes.fromhex(case["payload"])
    )
    assert produced.hex() == case["encoded"]


@pytest.mark.hardware
def test_firmware_emits_identical_bytes(sniffer_port):
    """Reads the firmware's boot-time conformance burst and compares bytes."""
    from esp32c6_sniffer.parser import StreamParser

    parser = StreamParser()
    frames = []
    deadline_frames = len(VECTORS)
    import time

    end = time.monotonic() + 10
    while time.monotonic() < end and len(frames) < deadline_frames:
        frames.extend(parser.feed(sniffer_port.read(4096)))

    assert len(frames) >= deadline_frames, (
        f"expected {deadline_frames} conformance frames, got {len(frames)}"
    )
    for case, frame in zip(VECTORS, frames):
        expected = encode_frame(
            FrameType(case["type"]), case["seq"], bytes.fromhex(case["payload"])
        )
        rebuilt = encode_frame(frame.ftype, frame.seq, frame.payload)
        assert rebuilt.hex() == expected.hex(), f"mismatch on {case['name']}"
```

`host/tests/conftest.py`:

```python
import pytest
import serial


def pytest_addoption(parser):
    parser.addoption("--port", default="COM3", help="serial port of the board")


def pytest_configure(config):
    config.addinivalue_line("markers", "hardware: requires the board attached")


@pytest.fixture
def sniffer_port(request):
    port = request.config.getoption("--port")
    ser = serial.Serial(port, 115200, timeout=0.2)
    try:
        ser.set_buffer_size(rx_size=1 << 20)  # Windows default is only 4 KB
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()
    yield ser
    ser.close()
```

- [ ] **Step 3: Run the host-only half and confirm it passes**

```bash
cd host && ./.venv/Scripts/python.exe -m pytest tests/test_conformance.py -q -m "not hardware"
```

Expected: `6 passed, 1 deselected`.

- [ ] **Step 4: Implement the firmware codec**

`firmware/main/frame.h`:

```c
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SN_MAGIC        0x5AC6u
#define SN_HEADER_LEN   10u
#define SN_MAX_PAYLOAD  4096u

typedef enum {
    SN_FRAME_PACKET = 1,
    SN_FRAME_LOG = 2,
    SN_FRAME_STATS = 3,
    SN_FRAME_HEARTBEAT = 4,
    SN_FRAME_CONTROL_REPLY = 5,
} sn_frame_type_t;

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final XOR.
 * Implemented here rather than using esp_rom_crc16_le, whose reflection and
 * final-XOR behaviour would have to be matched exactly on the host. */
uint16_t sn_crc16(const uint8_t *data, size_t len);

/* Writes a complete frame into `out`. Returns bytes written, or 0 if the
 * payload is too large or the buffer too small. */
size_t sn_frame_encode(uint8_t *out, size_t out_cap, sn_frame_type_t type,
                       uint16_t seq, const uint8_t *payload, size_t payload_len);

#ifdef __cplusplus
}
#endif
```

`firmware/main/frame.c`:

```c
#include "frame.h"

#include <string.h>

uint16_t sn_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x8000u) ? (uint16_t)((uint16_t)(crc << 1) ^ 0x1021u)
                                  : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

size_t sn_frame_encode(uint8_t *out, size_t out_cap, sn_frame_type_t type,
                       uint16_t seq, const uint8_t *payload, size_t payload_len)
{
    if (payload_len > SN_MAX_PAYLOAD) {
        return 0;
    }
    if (out_cap < SN_HEADER_LEN + payload_len) {
        return 0;
    }

    out[0] = (uint8_t)(SN_MAGIC & 0xFFu);
    out[1] = (uint8_t)((SN_MAGIC >> 8) & 0xFFu);
    out[2] = (uint8_t)type;
    out[3] = 0u; /* flags, reserved */
    out[4] = (uint8_t)(seq & 0xFFu);
    out[5] = (uint8_t)((seq >> 8) & 0xFFu);
    out[6] = (uint8_t)(payload_len & 0xFFu);
    out[7] = (uint8_t)((payload_len >> 8) & 0xFFu);

    const uint16_t crc = sn_crc16(out, 8);
    out[8] = (uint8_t)(crc & 0xFFu);
    out[9] = (uint8_t)((crc >> 8) & 0xFFu);

    if (payload_len > 0 && payload != NULL) {
        memcpy(out + SN_HEADER_LEN, payload, payload_len);
    }
    return SN_HEADER_LEN + payload_len;
}
```

Add `frame.c` to `firmware/main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c" "board.c" "frame.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio esp_driver_usb_serial_jtag
)
```

- [ ] **Step 5: Emit the conformance vectors at boot**

Replace `firmware/main/main.c`:

```c
#include "board.h"
#include "frame.h"

#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

static uint8_t s_scratch[SN_HEADER_LEN + SN_MAX_PAYLOAD];

/* Mirrors host/tests/vectors/golden.json. Keep the two in step. */
static void emit_conformance_vectors(void)
{
    uint8_t all_bytes[256];
    for (int i = 0; i < 256; i++) {
        all_bytes[i] = (uint8_t)i;
    }
    const uint8_t newline_bytes[] = {0x0a, 0x0d, 0x0a, 0x00, 0xff};
    const char hello[] = "hello";
    const char wrap[] = "wrap";
    const char logmsg[] = "I (123) tag: msg";

    struct {
        sn_frame_type_t type;
        uint16_t seq;
        const uint8_t *payload;
        size_t len;
    } cases[] = {
        {SN_FRAME_HEARTBEAT, 0, NULL, 0},
        {SN_FRAME_PACKET, 1, (const uint8_t *)hello, strlen(hello)},
        {SN_FRAME_PACKET, 2, newline_bytes, sizeof(newline_bytes)},
        {SN_FRAME_PACKET, 3, all_bytes, sizeof(all_bytes)},
        {SN_FRAME_PACKET, 65535, (const uint8_t *)wrap, strlen(wrap)},
        {SN_FRAME_LOG, 42, (const uint8_t *)logmsg, strlen(logmsg)},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const size_t n = sn_frame_encode(s_scratch, sizeof(s_scratch),
                                         cases[i].type, cases[i].seq,
                                         cases[i].payload, cases[i].len);
        if (n == 0) {
            ESP_LOGE(TAG, "encode failed for case %u", (unsigned)i);
            continue;
        }
        size_t written = 0;
        while (written < n) {
            const int w = usb_serial_jtag_write_bytes(s_scratch + written,
                                                      n - written,
                                                      pdMS_TO_TICKS(1000));
            if (w <= 0) {
                ESP_LOGW(TAG, "short write on case %u", (unsigned)i);
                break;
            }
            written += (size_t)w;
        }
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(sn_board_init(SN_ANTENNA_INTERNAL));

    const usb_serial_jtag_driver_config_t cfg = {
        .tx_buffer_size = 4096,
        .rx_buffer_size = 1024,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));

    /* Give the host time to open the port before the burst. */
    vTaskDelay(pdMS_TO_TICKS(2000));
    emit_conformance_vectors();
    ESP_LOGI(TAG, "conformance vectors emitted");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

- [ ] **Step 6: Build, flash, and run the hardware conformance test**

```bash
cd firmware && idf.py -p COM3 flash
cd ../host && ./.venv/Scripts/python.exe -m pytest tests/test_conformance.py -q -m hardware --port COM3
```

Expected: `1 passed`. A mismatch means the C and Python encoders disagree; fix
`frame.c` rather than regenerating the vectors, since `framing.py` is authoritative.

- [ ] **Step 7: Commit**

```bash
git add firmware/main host/tests
git commit -m "feat(fw): frame codec proven byte-identical to host via golden vectors"
```

---

### Task 5: Ring buffer, bulk writer, and TX health watchdog

**Files:**
- Create: `firmware/main/usb_link.h`
- Create: `firmware/main/usb_link.c`
- Modify: `firmware/main/CMakeLists.txt` (add `usb_link.c`)
- Modify: `firmware/main/main.c` (use the link instead of raw writes)

**Interfaces:**
- Consumes: `sn_frame_encode`, `SN_HEADER_LEN`, `SN_MAX_PAYLOAD` from Task 4.
- Produces: `esp_err_t sn_usb_link_init(void);` `bool sn_usb_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len);` returning false when the frame was dropped; `typedef struct { uint32_t frames_sent, frames_dropped_ringfull, short_writes, tx_stalls, bytes_sent; } sn_link_stats_t;` and `void sn_usb_link_get_stats(sn_link_stats_t *out);`

**Why the watchdog:** ESP-IDF issue #18490 reports the USB-Serial-JTAG transmit state machine stalling after a failed or partial write, on this exact chip revision. With USB as the only link there is no fallback, so the firmware must detect and recover.

- [ ] **Step 1: Write the header**

`firmware/main/usb_link.h`:

```c
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "frame.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t frames_sent;
    uint32_t frames_dropped_ringfull;
    uint32_t short_writes;
    uint32_t tx_stalls;
    uint32_t bytes_sent;
} sn_link_stats_t;

esp_err_t sn_usb_link_init(void);

/* Encodes and queues one frame. Assigns the sequence number internally.
 * Returns false if the ring buffer was full and the frame was dropped. */
bool sn_usb_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len);

void sn_usb_link_get_stats(sn_link_stats_t *out);

#ifdef __cplusplus
}
#endif
```

- [ ] **Step 2: Implement the link**

`firmware/main/usb_link.c`:

```c
#include "usb_link.h"

#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/task.h"

static const char *TAG = "usb_link";

#define RING_BYTES        (32 * 1024)
#define TX_CHUNK          1024
#define WRITE_TIMEOUT_MS  20
#define STALL_LIMIT       50   /* consecutive zero-byte writes before recovery */

static RingbufHandle_t s_ring;
static TaskHandle_t s_tx_task;
static sn_link_stats_t s_stats;
static portMUX_TYPE s_stats_lock = portMUX_INITIALIZER_UNLOCKED;
static uint16_t s_seq;

static void tx_task(void *arg)
{
    (void)arg;
    uint32_t consecutive_stalls = 0;

    while (true) {
        size_t got = 0;
        uint8_t *chunk = (uint8_t *)xRingbufferReceiveUpTo(
            s_ring, &got, pdMS_TO_TICKS(100), TX_CHUNK);
        if (chunk == NULL) {
            continue;
        }

        size_t written = 0;
        while (written < got) {
            const int w = usb_serial_jtag_write_bytes(
                chunk + written, got - written, pdMS_TO_TICKS(WRITE_TIMEOUT_MS));
            if (w > 0) {
                written += (size_t)w;
                consecutive_stalls = 0;
                if ((size_t)w < got - written) {
                    portENTER_CRITICAL(&s_stats_lock);
                    s_stats.short_writes++;
                    portEXIT_CRITICAL(&s_stats_lock);
                }
            } else {
                consecutive_stalls++;
                portENTER_CRITICAL(&s_stats_lock);
                s_stats.tx_stalls++;
                portEXIT_CRITICAL(&s_stats_lock);
                if (consecutive_stalls >= STALL_LIMIT) {
                    /* Issue #18490: the TX state machine can wedge after a
                     * partial or failed write. Nothing else can rescue it,
                     * so drop the rest of this chunk and let the host resync
                     * rather than blocking the pipeline forever. */
                    ESP_LOGW(TAG, "tx wedged, discarding %u bytes",
                             (unsigned)(got - written));
                    consecutive_stalls = 0;
                    break;
                }
            }
        }

        portENTER_CRITICAL(&s_stats_lock);
        s_stats.bytes_sent += (uint32_t)written;
        portEXIT_CRITICAL(&s_stats_lock);

        vRingbufferReturnItem(s_ring, chunk);
    }
}

esp_err_t sn_usb_link_init(void)
{
    const usb_serial_jtag_driver_config_t cfg = {
        .tx_buffer_size = 4096,
        .rx_buffer_size = 1024,
    };
    esp_err_t err = usb_serial_jtag_driver_install(&cfg);
    if (err != ESP_OK) {
        return err;
    }

    /* No-split: bytes are contiguous, so one write drains a whole chunk. */
    s_ring = xRingbufferCreate(RING_BYTES, RINGBUF_TYPE_BYTEBUF);
    if (s_ring == NULL) {
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(tx_task, "sn_tx", 4096, NULL, 10, &s_tx_task) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool sn_usb_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len)
{
    static uint8_t scratch[SN_HEADER_LEN + SN_MAX_PAYLOAD];

    portENTER_CRITICAL(&s_stats_lock);
    const uint16_t seq = s_seq++;
    portEXIT_CRITICAL(&s_stats_lock);

    const size_t n = sn_frame_encode(scratch, sizeof(scratch), type, seq,
                                     payload, len);
    if (n == 0) {
        return false;
    }

    if (xRingbufferSend(s_ring, scratch, n, 0) != pdTRUE) {
        portENTER_CRITICAL(&s_stats_lock);
        s_stats.frames_dropped_ringfull++;
        portEXIT_CRITICAL(&s_stats_lock);
        return false;
    }

    portENTER_CRITICAL(&s_stats_lock);
    s_stats.frames_sent++;
    portEXIT_CRITICAL(&s_stats_lock);
    return true;
}

void sn_usb_link_get_stats(sn_link_stats_t *out)
{
    portENTER_CRITICAL(&s_stats_lock);
    *out = s_stats;
    portEXIT_CRITICAL(&s_stats_lock);
}
```

Note `sn_usb_link_send` uses a single static scratch buffer, so it is **not**
re-entrant. Milestone 1 calls it from one task only. Task 6 respects this.

Update `firmware/main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c" "board.c" "frame.c" "usb_link.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio esp_driver_usb_serial_jtag esp_ringbuf
)
```

- [ ] **Step 3: Rewrite main.c to use the link**

Replace the body of `emit_conformance_vectors` writes and `app_main` in
`firmware/main/main.c` so the driver install and raw writes are gone:

```c
#include "board.h"
#include "frame.h"
#include "usb_link.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

static void emit_conformance_vectors(void)
{
    uint8_t all_bytes[256];
    for (int i = 0; i < 256; i++) {
        all_bytes[i] = (uint8_t)i;
    }
    const uint8_t newline_bytes[] = {0x0a, 0x0d, 0x0a, 0x00, 0xff};

    sn_usb_link_send(SN_FRAME_HEARTBEAT, NULL, 0);
    sn_usb_link_send(SN_FRAME_PACKET, (const uint8_t *)"hello", 5);
    sn_usb_link_send(SN_FRAME_PACKET, newline_bytes, sizeof(newline_bytes));
    sn_usb_link_send(SN_FRAME_PACKET, all_bytes, sizeof(all_bytes));
    sn_usb_link_send(SN_FRAME_PACKET, (const uint8_t *)"wrap", 4);
    sn_usb_link_send(SN_FRAME_LOG, (const uint8_t *)"I (123) tag: msg", 16);
}

void app_main(void)
{
    ESP_ERROR_CHECK(sn_board_init(SN_ANTENNA_INTERNAL));
    ESP_ERROR_CHECK(sn_usb_link_init());

    vTaskDelay(pdMS_TO_TICKS(2000));
    emit_conformance_vectors();
    ESP_LOGI(TAG, "conformance vectors emitted");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
```

**Sequence numbers now come from the link, not the caller**, so the hardware
conformance test must compare payloads rather than whole encoded frames.
Update `test_firmware_emits_identical_bytes` in `host/tests/test_conformance.py`,
replacing its final loop with:

```python
    for case, frame in zip(VECTORS, frames):
        assert frame.payload.hex() == case["payload"], f"payload mismatch on {case['name']}"
        assert int(frame.ftype) == case["type"], f"type mismatch on {case['name']}"
```

- [ ] **Step 4: Build, flash, verify**

```bash
cd firmware && idf.py -p COM3 flash
cd ../host && ./.venv/Scripts/python.exe -m pytest tests/ -q -m hardware --port COM3
```

Expected: `1 passed`. Payloads must survive intact, including the frame
containing `0x0a` bytes.

- [ ] **Step 5: Commit**

```bash
git add firmware/main host/tests/test_conformance.py
git commit -m "feat(fw): ring-buffered bulk USB writer with stall detection"
```

---

### Task 6: Route ESP_LOG output into LOG frames

**Files:**
- Create: `firmware/main/log_sink.h`
- Create: `firmware/main/log_sink.c`
- Modify: `firmware/main/CMakeLists.txt` (add `log_sink.c`)
- Modify: `firmware/main/main.c` (install the sink)

**Interfaces:**
- Consumes: `sn_usb_link_send` from Task 5.
- Produces: `void sn_log_sink_install(void);`

**Why:** USB-C is the only cable, so a physical UART console cannot be read. Logs
travel in-band as their own frame type and the host demultiplexes them.

- [ ] **Step 1: Implement the sink**

`firmware/main/log_sink.h`:

```c
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Redirects ESP_LOG output into SN_FRAME_LOG frames on the USB link.
 * Call after sn_usb_link_init(). */
void sn_log_sink_install(void);

#ifdef __cplusplus
}
#endif
```

`firmware/main/log_sink.c`:

```c
#include "log_sink.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "usb_link.h"

#define LOG_BUF_LEN 256

static SemaphoreHandle_t s_lock;
static char s_buf[LOG_BUF_LEN];

static int log_to_frame(const char *fmt, va_list args)
{
    /* Never block a logging call: if the lock is held, drop the line rather
     * than risk deadlocking a caller that may hold other locks. */
    if (s_lock == NULL || xSemaphoreTake(s_lock, 0) != pdTRUE) {
        return 0;
    }

    const int n = vsnprintf(s_buf, sizeof(s_buf), fmt, args);
    if (n > 0) {
        const size_t len = (n < (int)sizeof(s_buf)) ? (size_t)n
                                                    : sizeof(s_buf) - 1;
        sn_usb_link_send(SN_FRAME_LOG, (const uint8_t *)s_buf, len);
    }

    xSemaphoreGive(s_lock);
    return n;
}

void sn_log_sink_install(void)
{
    s_lock = xSemaphoreCreateMutex();
    /* Return value deliberately discarded: we never restore the old handler,
     * and ESP-IDF v6 builds warnings as errors, so an unused static would
     * break the build. */
    (void)esp_log_set_vprintf(log_to_frame);
}
```

Update `firmware/main/CMakeLists.txt`:

```cmake
idf_component_register(
    SRCS "main.c" "board.c" "frame.c" "usb_link.c" "log_sink.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio esp_driver_usb_serial_jtag esp_ringbuf
)
```

In `firmware/main/main.c`, add `#include "log_sink.h"` and call
`sn_log_sink_install();` immediately after `sn_usb_link_init()`.

**Re-entrancy note:** `sn_usb_link_send` uses a static scratch buffer, and the
log sink now calls it from arbitrary tasks. Make that buffer safe by adding a
mutex inside `usb_link.c`. Change `sn_usb_link_send` to take a lock created in
`sn_usb_link_init`:

```c
static SemaphoreHandle_t s_send_lock;   /* add near the other statics */
```

In `sn_usb_link_init`, before creating the task:

```c
    s_send_lock = xSemaphoreCreateMutex();
    if (s_send_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }
```

And wrap the body of `sn_usb_link_send` after the early `n == 0` check:

```c
    if (xSemaphoreTake(s_send_lock, pdMS_TO_TICKS(10)) != pdTRUE) {
        return false;
    }
    /* ... existing encode + xRingbufferSend body ... */
    xSemaphoreGive(s_send_lock);
```

Add `#include "freertos/semphr.h"` to `usb_link.c`.

- [ ] **Step 2: Write the hardware test**

Append to `host/tests/test_conformance.py`:

```python
@pytest.mark.hardware
def test_log_output_arrives_as_log_frames_not_raw_bytes(sniffer_port):
    """Log text must be framed, never interleaved raw into the stream."""
    import time

    from esp32c6_sniffer.framing import FrameType
    from esp32c6_sniffer.parser import StreamParser

    parser = StreamParser()
    frames = []
    end = time.monotonic() + 12
    while time.monotonic() < end:
        frames.extend(parser.feed(sniffer_port.read(4096)))
        if any(f.ftype is FrameType.LOG for f in frames):
            break

    log_frames = [f for f in frames if f.ftype is FrameType.LOG]
    assert log_frames, "no LOG frames received"
    assert parser.bytes_discarded == 0, (
        f"{parser.bytes_discarded} raw bytes outside frames — log output is "
        "leaking into the stream"
    )
```

- [ ] **Step 3: Build, flash, run**

```bash
cd firmware && idf.py -p COM3 flash
cd ../host && ./.venv/Scripts/python.exe -m pytest tests/ -q -m hardware --port COM3
```

Expected: `2 passed`. `bytes_discarded == 0` is the real assertion here; a
non-zero value means unframed bytes are reaching the host.

- [ ] **Step 4: Commit**

```bash
git add firmware/main
git commit -m "feat(fw): route ESP_LOG into in-band LOG frames over the single cable"
```

---

### Task 7: Throughput benchmark

**Files:**
- Create: `firmware/main/bench.h`
- Create: `firmware/main/bench.c`
- Modify: `firmware/main/CMakeLists.txt` (add `bench.c`)
- Modify: `firmware/main/main.c` (start the benchmark)
- Create: `host/src/esp32c6_sniffer/benchmark.py`
- Modify: `docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md` (record the result)

**Interfaces:**
- Consumes: `sn_usb_link_send`, `sn_usb_link_get_stats`, `sn_link_stats_t` from Task 5.
- Produces: `void sn_bench_start(size_t payload_len);` on the firmware; `main(argv)` CLI entry point on the host.

**This task answers the open question the whole milestone exists for.**

- [ ] **Step 1: Implement the generator**

`firmware/main/bench.h`:

```c
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Streams PACKET frames of `payload_len` bytes as fast as the link accepts
 * them, forever, emitting a STATS frame once per second. */
void sn_bench_start(size_t payload_len);

#ifdef __cplusplus
}
#endif
```

`firmware/main/bench.c`:

```c
#include "bench.h"

#include <string.h>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "usb_link.h"

static size_t s_payload_len;
static uint8_t s_pattern[SN_MAX_PAYLOAD];

static void bench_task(void *arg)
{
    (void)arg;
    int64_t next_stats_us = esp_timer_get_time() + 1000000;

    while (true) {
        sn_usb_link_send(SN_FRAME_PACKET, s_pattern, s_payload_len);

        const int64_t now = esp_timer_get_time();
        if (now >= next_stats_us) {
            next_stats_us = now + 1000000;
            sn_link_stats_t st;
            sn_usb_link_get_stats(&st);
            sn_usb_link_send(SN_FRAME_STATS, (const uint8_t *)&st, sizeof(st));
        }

        /* Yield so the TX task and the idle task can run. */
        taskYIELD();
    }
}

void sn_bench_start(size_t payload_len)
{
    if (payload_len > SN_MAX_PAYLOAD) {
        payload_len = SN_MAX_PAYLOAD;
    }
    s_payload_len = payload_len;
    for (size_t i = 0; i < payload_len; i++) {
        s_pattern[i] = (uint8_t)(i & 0xFF);
    }
    xTaskCreate(bench_task, "sn_bench", 4096, NULL, 5, NULL);
}
```

In `firmware/main/main.c`, add `#include "bench.h"` and replace the idle loop:

```c
    sn_bench_start(256);   /* payload size under test */

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
```

Update `firmware/main/CMakeLists.txt` to add `"bench.c"` to `SRCS` and
`esp_timer` to `REQUIRES`.

- [ ] **Step 2: Implement the host benchmark**

`host/src/esp32c6_sniffer/benchmark.py`:

```python
"""Measures sustained USB throughput from the board.

No published throughput figure exists for the ESP32-C6's USB-Serial-JTAG.
This produces one.
"""

from __future__ import annotations

import argparse
import struct
import time

import serial

from .framing import FrameType
from .parser import SequenceTracker, StreamParser

_STATS_STRUCT = struct.Struct("<5I")  # matches sn_link_stats_t


def run(port: str, seconds: float) -> dict[str, float | int]:
    ser = serial.Serial(port, 115200, timeout=0.05)
    try:
        ser.set_buffer_size(rx_size=1 << 20)  # Windows default is only 4 KB
    except (AttributeError, OSError):
        pass
    ser.reset_input_buffer()

    parser = StreamParser()
    tracker = SequenceTracker()
    payload_bytes = 0
    packet_frames = 0
    last_stats: tuple[int, ...] | None = None

    start = time.monotonic()
    end = start + seconds
    idle_reads = 0
    while time.monotonic() < end:
        chunk = ser.read(8192)
        if chunk:
            idle_reads = 0
            frames = parser.feed(chunk)
        else:
            # Nothing for ~0.5 s. A frame may be stalled mid-payload because
            # its tail was discarded; only we can break that deadlock.
            idle_reads += 1
            frames = parser.force_resync() if idle_reads >= 10 else []
            if frames:
                idle_reads = 0
        for frame in frames:
            tracker.observe(frame.seq)
            if frame.ftype is FrameType.PACKET:
                packet_frames += 1
                payload_bytes += len(frame.payload)
            elif frame.ftype is FrameType.STATS:
                if len(frame.payload) >= _STATS_STRUCT.size:
                    last_stats = _STATS_STRUCT.unpack(
                        frame.payload[: _STATS_STRUCT.size]
                    )
    elapsed = time.monotonic() - start
    ser.close()

    result: dict[str, float | int] = {
        "elapsed_s": round(elapsed, 3),
        "packet_frames": packet_frames,
        "payload_bytes": payload_bytes,
        "payload_kB_per_s": round(payload_bytes / elapsed / 1000, 1),
        "frames_per_s": round(packet_frames / elapsed, 1),
        "frames_missed_host_side": tracker.total_missed,
        "resyncs": parser.resync_count,
        "bytes_discarded": parser.bytes_discarded,
    }
    if last_stats:
        (sent, dropped_ringfull, short_writes, tx_stalls, bytes_sent) = last_stats
        result.update(
            {
                "fw_frames_sent": sent,
                "fw_dropped_ringfull": dropped_ringfull,
                "fw_short_writes": short_writes,
                "fw_tx_stalls": tx_stalls,
                "fw_bytes_sent": bytes_sent,
            }
        )
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="ESP32-C6 USB throughput benchmark")
    ap.add_argument("--port", default="COM3")
    ap.add_argument("--seconds", type=float, default=20.0)
    args = ap.parse_args()

    for key, value in run(args.port, args.seconds).items():
        print(f"{key:28s} {value}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Measure across payload sizes**

For each of 64, 128, 256, 512, 1024 and 1500 bytes, edit the `sn_bench_start(N)`
argument in `main.c`, then:

```bash
cd firmware && idf.py -p COM3 flash
cd ../host && ./.venv/Scripts/python.exe -m esp32c6_sniffer.benchmark --port COM3 --seconds 20
```

Record `payload_kB_per_s`, `frames_per_s`, `frames_missed_host_side`,
`fw_dropped_ringfull` and `fw_tx_stalls` for each size.

Expected: throughput rises with payload size as per-frame overhead amortises.
The spec's planning figure is roughly 770 kB/s, measured on an ESP32-S3 rather
than a C6, so treat any result between 500 kB/s and 1.2 MB/s as plausible and
anything outside that range as worth investigating before trusting.

- [ ] **Step 4: Run the benchmark for 30 minutes at the best payload size**

The transmit lockup in issue #18490 appears after minutes to hours, so a short
run does not exercise it.

```bash
cd host && ./.venv/Scripts/python.exe -m esp32c6_sniffer.benchmark --port COM3 --seconds 1800
```

Record whether `fw_tx_stalls` grows and whether throughput degrades over time.

- [ ] **Step 5: Record the measured figures in the spec**

In `docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md`, replace open
question 1 in §10 with a table of the measured results, and update the §4
transport budget table to cite the real C6 figure instead of the S3 proxy.
Keep the S3 figure alongside it for comparison.

- [ ] **Step 6: Commit**

```bash
git add firmware/main host/src/esp32c6_sniffer/benchmark.py docs/
git commit -m "feat: USB throughput benchmark and first measured C6 figures"
```

---

## Milestone exit criteria

- [ ] `pytest` passes with no hardware attached (framing and parser).
- [ ] Hardware conformance test passes: firmware and host produce identical bytes.
- [ ] A payload containing `0x0a` bytes survives the link byte-for-byte.
- [ ] `parser.bytes_discarded == 0` on a clean run, proving no unframed bytes leak.
- [ ] Sustained throughput measured across six payload sizes and recorded in the spec.
- [ ] A 30-minute run completed, with transmit stall behaviour recorded.

Milestone 2 (802.15.4 into Wireshark) begins only once these hold.
