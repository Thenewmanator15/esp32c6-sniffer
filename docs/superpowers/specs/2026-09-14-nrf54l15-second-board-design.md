# A second board: the XIAO nRF54L15

## What this is

The sniffer currently assumes one board type. This design makes the board a
variable, and adds a Seeed XIAO nRF54L15 as the second value it can take.

802.15.4 first, BLE afterwards as its own piece of work. The nRF54L15 has no
Wi-Fi radio at all, so Wi-Fi remains a C6 capability and always will be.

## The hardware, verified rather than assumed

The board on this machine is a **Seeed XIAO nRF54L15**, not Nordic's nRF54L15
DK. It enumerates as USB `2886:0066`, a composite device presenting a HID
interface, a CMSIS-DAP v2 adapter and a USB CDC serial port. There is no
SEGGER J-Link on this machine, which is what a Nordic DK would present.

That CDC port is almost certainly the "unrelated USB serial device on COM4"
that `default_port()` in the extcap already complains about.

Three facts follow, and all three shape the design:

**The nRF54L15 has no USB device controller.** Within the nRF54L family, USB
is on the LM20A and LM20B only. The XIAO works around this with an onboard
SAMD11 running CMSIS-DAP, which bridges a SoC UART to USB CDC. So the data
path is nRF54L15 -> UART -> SAMD11 -> USB, and not the native USB the C6 uses
at a measured ~810 kB/s.

This matters less than it first appears. 802.15.4 is 250 kbps on air, about
31 kB/s of ceiling, so even a 1 Mbaud UART has roughly 3x headroom. The
transport budget measured in milestone 1 only ever mattered for Wi-Fi, which
this part cannot do. Sustained BLE connection-following on the 1M PHY is the
one case that could outrun the bridge, and it is unmeasured.

**Nordic's own sniffer firmware does not support this part.** The nRF Sniffer
for 802.15.4 lists the nRF52840 DK, nRF52840 Dongle, nRF5340 DK and nRF54LM20
Dongle. The nRF54L15 is not among them; the nRF54L family member supported is
the LM20, a different device. There is therefore no "just flash Nordic's
firmware" option, and firmware must be written either way.

**Their wire format would be a poor inheritance anyway.** The sample emits
ASCII lines of the form `received: <hex> power: <dBm> lqi: <n> time: <us>`.
Hex-encoding doubles every payload byte on what is already the slowest link in
the system, and it would put a second wire format into a codebase that
deliberately has one.

## Decision

Write Zephyr firmware that speaks the existing `0x5AC6` framing and the
existing `Command` enum, and generalise the host to know about boards.

The radio layer is worth cribbing from Nordic's sample -- their use of
Zephyr's raw 802.15.4 driver is the useful half. Their output stage is the
half to leave behind.

The alternative considered and rejected was to keep Nordic's ASCII format and
translate on the host. It pays the porting cost regardless (the sample does
not target this part), costs ~2.4x the bytes on the constrained link, and
strands every feature that makes this tool worth using: mid-capture channel
changes, the spectrum survey, drop counters, self-describing pcapng.

A third option -- special-case `nrf54l15-802154` without generalising -- was
rejected because the special-casing lands in five places and gets paid for
again when BLE arrives.

## Board identity

Identity must be known **before any port is opened**. This is not a
preference; `test_no_board_still_advertises_the_interfaces` requires the
extcap to list interfaces with nothing plugged in, so Wireshark can show them
in advance. Identity learned over the wire arrives too late to name an
interface, which rules out a `GET_BOARD` control command as the primary
mechanism.

It is already free. `find_board_ports()` enumerates with `p.vid` and `p.pid`
in hand and discards both.

    0x303A:0x1001   Seeed XIAO ESP32-C6
    0x2886:0x0066   Seeed XIAO nRF54L15

So `find_board_ports()` returns `(port, board)` pairs, and a `BOARDS` table
keyed by VID/PID carries the display name, the radios the board has, and the
controls its dialog should offer.

An unrecognised VID/PID is ignored rather than guessed at. Guessing produces a
board whose capabilities are wrong, which is worse than a board that is absent.

## Capabilities

|                | XIAO ESP32-C6          | XIAO nRF54L15     |
|----------------|------------------------|-------------------|
| Radios         | 802.15.4, Wi-Fi, BLE   | 802.15.4, BLE     |
| `SET_ANTENNA`  | yes, a real RF switch  | no                |
| Energy detect  | yes                    | to be confirmed   |
| Timestamps     | ~0.5 us, C6 mechanism  | unknown           |

`SET_ANTENNA` exists on the C6 because that board has an FM8625H RF switch on
GPIO3/GPIO14, documented in `firmware/main/board.h`. It is a property of the
board, not of the radio, which is precisely why capabilities belong in the
board table.

Capabilities gate the dialog, so an interface that cannot select an antenna
has no antenna dropdown, rather than one that lies.

## Interface naming

`INTERFACES` stops being a flat dict of three hardcoded `esp32c6-*` entries
and becomes generated: board x radio. The existing `<radio>@<port>` scheme is
unchanged, and the board name is already inside the radio name today.

    esp32c6-802154          esp32c6-wifi        esp32c6-ble
    nrf54l15-802154@COM4    nrf54l15-ble@COM4   (ble only once step 6 lands)

`split_interface()` and `PORT_SEPARATOR` need no change.

A board's radio list records **what its firmware implements, not what its
silicon can do**. So the nRF entry lists 802.15.4 only until step 6 lands, and
`nrf54l15-ble@COM4` does not appear in Wireshark before there is firmware
behind it. An interface that cannot capture is worse than an absent one: it is
selectable, and it fails at the point the operator has already committed to a
capture.

The bare-name rule becomes subtler. Today names go bare when exactly one board
is present. With two board kinds "one board" is ambiguous, so the rule is:
bare only when exactly one board is present overall. A lone C6 is then
byte-identical to today and nobody's saved capture options move. Plugging a
XIAO in renames the C6's interfaces -- which is already the behaviour for a
second C6, and already covered by `test_two_boards_give_one_set_each`.

## Firmware

`frame.c` is shared, not mirrored. It includes `<string.h>`, `<stdint.h>` and
`<stddef.h>` and no ESP-IDF header, so it compiles verbatim under Zephyr.
Moving it and `frame.h` to `firmware/shared/` and compiling that same file
into both builds makes byte-identity a property of the build rather than
something tests must verify. The golden vectors then guard only C-versus-Python
drift, which is what they were written for. The `Command` enum in `control.h`
gets the same treatment.

That leaves three things for the Zephyr app:

- **Radio.** Zephyr's raw 802.15.4 mode (`CONFIG_IEEE802154_RAW_MODE`), which
  yields frames without a network stack. Cribbed from Nordic's sample.
- **Transport.** UART to the SAMD11. The baud rate is to be determined by
  measurement, not assumption, using the existing rig: `benchmark.py`,
  `bench.c`, `bench-sweep.ps1`. Milestone 1 for this board is the existing
  milestone 1 re-run on a different link.
- **Logging.** The C6 redirects `ESP_LOG` into `LOG` frames because USB-C is
  its only channel. The XIAO has the same problem with one UART, and Zephyr
  takes a custom log backend cleanly. Same solution, different API.

The app lives in `firmware-nrf54l15/`, separate from `firmware/`, because
ESP-IDF and Zephyr cannot share a build system even when they share source.

## Version handshake

`GET_INFO` returns a bare 32-bit integer today, compared against a single
`EXPECTED_FIRMWARE_VERSION`. The wire format stays one shared version; each
board reports its own firmware version against its own expected value. The
mismatch message already names both versions and grows to name the board.

## Testing

Nearly all of it needs no hardware. The host half is pure Python and
`test_multi_board.py` already establishes the pattern of monkeypatching
`find_board_ports`. New cases in that style:

- a XIAO alone gets bare `nrf54l15-*` names
- a C6 plus a XIAO yields four interfaces while only 802.15.4 firmware exists
  for the nRF -- three for the C6 and one for the XIAO. It becomes five when
  step 6 lands BLE, and never six: there is no Wi-Fi radio on the nRF to name
- the antenna option is absent from the XIAO's config output
- an unknown VID/PID is ignored rather than guessed at
- a lone C6 produces output identical to today, option for option

The firmware half needs no new test code. A Zephyr conformance build emitting
the same golden burst is held to `golden.json` by the existing
`test_firmware_emits_identical_bytes`, run as `pytest -m hardware --port COM4`.

## Sequencing

**0. Spike, before anything else.** Install nRF Connect SDK. Build a bare
Zephyr app for `xiao_nrf54l15`. Prove it flashes over CMSIS-DAP; prove
`CONFIG_IEEE802154_RAW_MODE` is available for this target and receives
promiscuously; measure what the SAMD11 bridge sustains. A failure here
invalidates everything below it, which is why it comes first.

1. **Share `frame.c`.** Pure refactor. C6 output stays byte-identical and the
   golden vectors prove it.
2. **Host abstraction.** `BOARDS`, discovery pairs, generated `INTERFACES`,
   capability gating, per-board version expectations. No hardware needed. C6
   behaviour unchanged.
3. **Zephyr conformance build.** Existing conformance test, pointed at COM4.
4. **Zephyr capture build.** `PACKET` frames, `SET_CHANNEL`, `GET_INFO`, drop
   counters.
5. **Into Wireshark.** `nrf54l15-802154@COM4` capturing live Zigbee and Thread.
6. **BLE**, as its own piece of work on a proven foundation.

Steps 1 and 2 are worth having even if step 0 kills the board.

## Risks

- **Zephyr 802.15.4 on this exact target is unproven.** Board support exists
  and the SoC has the radio, but whether the driver is wired up for the
  `xiao_nrf54l15` board target is a build-and-see. Retired by step 0.
- **Bridge throughput is unmeasured.** The arithmetic says there is headroom
  for 802.15.4. Arithmetic is not a measurement.
- **Energy detect may have no equivalent** in Zephyr's raw driver, which would
  make the spectrum survey C6-only. Acceptable, and the capability table
  already expresses it.
- **Timestamps will not match.** The ~0.5 us figure comes from a C6-specific
  mechanism, validated against the standard's fixed acknowledgement
  turnaround. The nRF will need its own characterisation, and its own claim.
- **BLE may outrun the bridge.** Unmeasured, and deferred to step 6.

## Out of scope

Cross-board time synchronisation. Two boards already appear as two Wireshark
interfaces and can capture simultaneously; merging them into one timeline with
a shared clock is a separate problem and is not required by anything here.
