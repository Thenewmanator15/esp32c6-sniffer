# nRF54L15 firmware

The Seeed XIAO nRF54L15 half of the sniffer. Speaks the same wire format as
the ESP32-C6 firmware by compiling the same `firmware/shared/frame.c`, so the
two boards cannot drift from each other.

Separate from `firmware/` because ESP-IDF and Zephyr cannot share a build
system, even when they share source.

## State

**The framing works. The radio does not.**

The conformance build is held to `host/tests/vectors/golden.json` by the same
test that holds the C6, and passes. 802.15.4 capture is blocked: frames never
reach the driver, for reasons that are not in this firmware. See
[docs/2026-09-14-nrf54l15-spike.md](../docs/2026-09-14-nrf54l15-spike.md)
before spending time on it.

## Toolchain

nRF Connect SDK **v3.4.0** (Zephyr 4.4.0, west 1.5.0), installed with
`nrfutil sdk-manager`. openocd is **not** part of it and must be installed
separately -- `winget install xpack-dev-tools.openocd-xpack`.

Set up the environment once per shell:

```powershell
nrfutil sdk-manager toolchain env --ncs-version v3.4.0 --as-script powershell | Out-File ncsenv.ps1
. .\ncsenv.ps1
```

## Build and flash

The board target needs its SoC and cpucluster qualifiers. A bare
`xiao_nrf54l15` does not resolve.

```powershell
west build --no-sysbuild -b xiao_nrf54l15/nrf54l15/cpuapp -d G:\dev\scratch\nrf\bsn <this directory> --pristine -- -DSN_MODE=0
west flash -d G:\dev\scratch\nrf\bsn --runner openocd
```

**Keep the build directory short.** Zephyr appends a deep
`zephyr/include/generated/...` tree, and a long build path pushes the real
paths past Windows' 260-character `MAX_PATH`. The failure is not obvious: it
surfaces inside `dts_edt_pickle` as

    1: "Abnormal exit with child return code: no such file or directory"

`LongPathsEnabled=1` in the registry does not help, because Zephyr's `dtc` and
Python helpers do not opt in through their manifests.

**openocd is the only runner that works here.** `jlink` and `nrfjprog` need a
SEGGER probe; this board has a SAMD11 running CMSIS-DAP. `nrfutil` can see the
board -- `nrfutil device list` names it -- but enumerates it as a serial device
with no programming trait, and fails with "Unable to find a board".

## SN_MODE

Mirrors `firmware/main`, so both boards are driven the same way.

| Mode | What it does |
|---|---|
| 0 | Conformance burst. The default, and what the host test suite needs. |
| 2 | Capture. |

## Testing

With the board attached, from `host/`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_conformance.py -v -m hardware --port COM4
```

No test code is specific to this board. The suite takes a `--port` and does
not care which firmware is behind it, which is the point: one set of golden
vectors holds both boards.

## Rules for the shared source

`firmware/shared/frame.c` and `firmware/shared/commands.h` are compiled into
both firmwares and must depend on nothing but `<stddef.h>`, `<stdint.h>` and
`<string.h>`. Adding an SDK header to either breaks the other board's build --
which is the mechanism working, not failing.

## Why there is no USB in prj.conf

The nRF54L15 has no USB device controller; within the nRF54L family that is
the LM20A and LM20B only. The host is reached through the SAMD11's USB CDC
bridge over `uart20`. Nordic's own `802154_sniffer` sample configures CDC-ACM
directly and cannot run on this part for exactly that reason.

`uart20` defaults to 115200 baud, about 11.5 kB/s. An 802.15.4 channel can
produce roughly 31 kB/s, so that default is not merely slow, it is
insufficient for capture. Raising it is a measurement nobody has made yet.

## Why the console and shell are off

There is one UART and the capture stream owns it. Anything else writing to it
puts unframed bytes into the data path, which is what
`test_no_unframed_bytes_once_synchronised` exists to catch.
