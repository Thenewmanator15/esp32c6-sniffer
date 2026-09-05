# ESP32-C6 tri-radio passive sniffer — design

**Date:** 2026-09-05
**Status:** Draft for review
**Hardware:** Seeed Studio XIAO ESP32-C6 (ESP32-C6FH4, QFN32, rev v0.2), COM3
**Toolchain:** ESP-IDF v6.1 (pinned tag), Python host, Wireshark

---

## 1. Purpose and scope

A passive wireless capture tool. The board sniffs one radio at a time and streams
framed packets over USB-C to a PC, where a Wireshark extcap plugin presents them as
a live capture interface.

**In scope:** IEEE 802.15.4 (Zigbee/Thread/Matter), Wi-Fi (802.11 2.4 GHz), BLE
advertisements. Live Wireshark capture. A thin CLI for headless capture and
benchmarking.

**Explicitly out of scope:** transmit of any kind. No deauthentication, no injection,
no attack modules, no active probing. This keeps the tool unambiguously a
diagnostics and protocol-learning instrument and keeps the codebase small. It is
intended for networks and devices the operator owns or is authorised to test.

**Not attempted:** decryption. We hold no keys; WPA2/WPA3 payloads stay encrypted.

---

## 2. Hardware, as confirmed

Read from the chip itself via esptool, not from documentation:

```
Chip type:  ESP32-C6FH4 (QFN32) (revision v0.2)
Features:   Wi-Fi 6, BT 5 (LE), IEEE802.15.4, Single Core + LP Core,
            160MHz, Embedded Flash 4MB
USB mode:   USB-Serial/JTAG
MAC:        aa:bb:cc:dd:ee:ff
```

512 KB SRAM, no PSRAM. Single high-performance RISC-V core (RV32IMAC) plus an LP
core. USB enumerates as VID `303A` PID `1001`, a composite device with a CDC-ACM
interface and a JTAG interface.

The board arrived running Espressif's `esp_ot_rcp` (OpenThread Radio Co-Processor),
built 2026-05-23 against ESP-IDF v6.0-beta1. Nothing on it is precious.

---

## 3. Core architecture

**Mode switching is expressed as Wireshark interface selection.** A pcap file carries
exactly one link-layer type, and each radio needs a different one. So the extcap
plugin advertises three interfaces. Choosing one selects the radio and guarantees the
link type is correct.

| Interface | Link type | Honest ceiling |
|---|---|---|
| `esp32c6-802154` | `IEEE802_15_4_TAP` (283) | Strong. Full promiscuous capture with RSSI/LQI/channel. |
| `esp32c6-wifi` | `IEEE802_11_RADIOTAP` (127) | Good. Full payloads except MIMO frames, which yield length only. 2.4 GHz only. |
| `esp32c6-ble` | `BLUETOOTH_HCI_H4` (187) | Weak. Advertisements only, reconstructed from host-stack events. |

### Why one radio at a time

The C6 has a single 2.4 GHz RF front end shared by all three radios. Espressif's
coexistence documentation states a module cannot receive while another is
transmitting or receiving, and arbitrates by time-division. The support matrix lists
**BLE scan + 802.15.4 scan as unsupported** and Wi-Fi sniffer + BLE as
"conditionally supported, unstable". Simultaneous full-duty tri-radio capture is not
physically available. Anyone claiming otherwise is wrong.

### Why BLE is HCI, not link-layer

The C6's radio blob exposes no raw link-layer access. What we get is a GAP discovery
callback from the host stack, which is HCI-level information. Encoding it as
link-layer would imply a radio capture we did not perform. We map the advertising PDU
type honestly from the event type. (GhostESP hardcodes `ADV_IND` and a report count
of 1, so scan responses and non-connectable adverts are mislabelled in its output.
Do not copy this.)

---

## 4. Transport budget

USB 2.0 full speed, 12 Mbit/s. The datasheet explicitly excludes high-speed mode.
The C6 has **no USB-OTG peripheral**, so a custom high-throughput device class is not
implementable. There is no second wire; USB-C is the only link.

| Quantity | Value |
|---|---|
| Theoretical full-speed bulk maximum | ~1.2 MB/s |
| Best measured figure available (ESP32-S3, not C6) | ~770 kB/s |
| 802.15.4 saturated channel | ~31 kB/s |
| BLE advertisements | a few kB/s |
| Wi-Fi 2.4 GHz peak | 150 Mbit/s, ~20x over budget |

**No C6 throughput measurement has been published anywhere.** Establishing it is
milestone 1.

Consequence: 802.15.4 and BLE fit comfortably and should never drop. Wi-Fi cannot
fit, and no transport available on this chip closes that gap. The answer is on-chip
filtering and truncation, not a faster wire.

---

## 5. Firmware design (ESP-IDF v6.1, C)

Pin the `v6.1` **tag**, not `release/v6.1` — the branch has already moved past the tag
and is not reproducible.

```
firmware/
  board/      antenna switch, console routing, power management
  radio/      one driver per radio, common capture callback
  core/       mode manager, frame envelope, drop accounting
  transport/  ring buffer, USB writer, TX health watchdog
```

### Board bring-up (mandatory, board-specific)

| Signal | GPIO | Role | Levels |
|---|---|---|---|
| RF switch power | 3 | Powers the FM8625H switch | **LOW = on** |
| Antenna select | 14 | Chooses antenna | LOW = ceramic, HIGH = external U.FL |

**GPIO3 must be driven LOW unconditionally at startup, before any radio is enabled.**
At reset it floats, a 10 kΩ pull-up holds the P-FET off, and the RF switch sits
**unpowered**. The default is not "internal antenna selected"; it is a dead switch the
radio reaches its antenna through only by leakage, measured by the community at
roughly 30 dB down. Skipping this silently cripples every capture on both antennas.

The Arduino core does this at boot, so nobody using Arduino discovers it. Seeed's own
ESP-IDF documentation never mentions the antenna switch. This is the single most
consequential board-specific requirement.

Both pins are internal-only and conflict with nothing on the headers. Both must be
**held**, not pulsed. Re-assert after any radio re-init.

Antenna choice is exposed as a per-capture extcap option. Community measurements put
external between 5 and 10 dB ahead of the ceramic antenna once the switch is live,
though the two sources disagree on the figure.

### Console and power

- Console on the default UART, GPIO16 (header pin D6). No custom pin config needed.
- **`CONFIG_ESP_CONSOLE_SECONDARY_NONE=y` is required.** The default routes console
  output to USB-Serial-JTAG *as a secondary channel even when the primary is a UART*,
  which would inject log text into the capture stream.
- Power management disabled. Light sleep gates the USB PHY clock and kills the link,
  and ESP-IDF will not stop you entering it.
- Keep logging *enabled* (routed to UART) rather than disabled — issue #17432 reports
  USB-Serial-JTAG failing to initialise on C6 when logging is off.

### Radio legs

**802.15.4.** `esp_ieee802154_set_promiscuous(true)` — which also disables auto-ACK
RX/TX and enhanced-ACK TX, correct for passive observation. The driver hands us a
buffer we own until `esp_ieee802154_receive_handle_done()`, so we stream from it
**without copying**. Raise `CONFIG_IEEE802154_RX_BUFFER_SIZE` above its default of 20.
Enable `CONFIG_IEEE802154_DEBUG=y` during bring-up: the "Rx buffer full" warning is
compiled out otherwise, making overflow completely invisible.

**Wi-Fi.** Promiscuous mode with `wifi_promiscuous_filter_t` (note: the mask is a
**pass** mask despite the name; `MASK_ALL` means deliver everything). Buffer lifetime
is undocumented and the driver is closed-source, so **copy immediately**. Apply a
configurable snapshot length. Do not budget on the filter reducing driver-side RX
load — evidence suggests it is partly hardware and partly a software check.

**BLE.** NimBLE observer via `ble_gap_disc`. Synthesise the HCI advertising report
with the **correct** PDU type derived from the event.

### Transport

- Compose frames directly into an `esp_ringbuf` **no-split** buffer using
  `xRingbufferSendAcquire()` / `SendComplete()`, so the header, metadata and payload
  are assembled in place.
- Drain with bulk `usb_serial_jtag_write_bytes()`.
- **Never write capture data through stdio.** The VFS path is byte-at-a-time *and*
  applies CRLF translation, which would insert `0x0D` before every `0x0A` byte in
  binary payloads. That corrupts captures invisibly and produces plausible-looking
  wrong files. The existing reference C6 sniffer writes via `fwrite(..., stdout)` and
  appears to carry this bug.
- Raise `tx_buffer_size` well above its 256-byte default to absorb bursts.
- Place the RX callback, ring writer and USB feed in IRAM. Raise radio ISR priority
  above the USB ISR using the C6's flexible interrupt controller.

### Framing protocol

Length-prefixed, with a magic marker, message type, sequence number and a CRC-16 over
the **header only**. Payload integrity is already covered by the radio FCS and by USB's
own per-packet CRC.

Message types: `PACKET`, `LOG`, `STATS`, `HEARTBEAT`, `CONTROL_REPLY`.

- **Logs travel in-band.** With only one cable we cannot read a physical UART. Hook
  `esp_log_set_vprintf()` and emit log output as `LOG` frames. The host demultiplexes:
  packets to Wireshark, logs to a console.
- **A resynchronisation marker is required**, because the transport silently discards
  bytes when the host stops reading (see §7).
- **Sequence numbers** so host-side gaps are detectable.
- **`STATS` frames carry our own drop counters** from every queue boundary. Nothing in
  the stack reports drops: Espressif proposed a Wi-Fi promiscuous overflow counter and
  closed the issue without adding one, and the 802.15.4 warning is compiled out by
  default. Without our own counters we cannot distinguish a quiet channel from a
  broken pipeline.
- **`HEARTBEAT` frames** so the host can distinguish a quiet radio from a dead link.

### Timestamps

The two radios behave oppositely, and not in the intuitive direction.

- **Wi-Fi: genuinely hardware-latched** from the radio's TSF counter. Use it. Two
  traps: it is 32-bit microseconds and **wraps every ~72 minutes**, and on the C6
  `wifi_pkt_rx_ctrl_t` is a typedef of `esp_wifi_rxctrl_t` with a **different layout**
  than on ESP32/C3 — code ported from an ESP32 sniffer reads the wrong fields.
- **802.15.4: NOT hardware**, despite a struct comment claiming the SFD reception time.
  The driver reads `esp_timer_get_time()` inside the ISR, so it carries interrupt
  jitter. The jitter is independent of frame length, so raising ISR priority and IRAM
  placement is the only available lever.

Anchor `esp_timer` to wall clock once at session start via a host handshake.

---

## 6. Host design (Python)

```
host/
  extcap/    Wireshark plugin, three interfaces
  sniffer/   framing parser, pcap writer, serial link
  cli/       headless capture, throughput benchmark
```

Installs to `%APPDATA%\Wireshark\extcap` — per-user, no admin rights.

Per-interface options: channel, antenna (internal/external), snapshot length,
frame-type filters. **No baud-rate option** — this is a USB CDC virtual port with no
physical line rate, and the setting is discarded. Existing projects expose one as a
leftover from bridge-chip designs; it is misleading here.

**Host read performance is a correctness requirement, not a nicety** (§7). Raise the
serial receive buffer well above pyserial's 4 KB Windows default, and keep reads
outstanding continuously.

Drop and overflow statistics are surfaced to the operator, not swallowed.

---

## 7. Known risks

**USB transmit lockup — highest risk, no fallback.** ESP-IDF issue #18490 reports the
USB-Serial-JTAG TX state machine stalling after minutes to hours when a write fails or
completes partially. The reporter's hardware is listed as "ESP32-C6FH4 (QFN32)
(revision v0.2)" — our exact part — and it was filed against `esp_ot_rcp`, which is
what this board shipped running. Espressif identified the cause; no fix is merged. It
is a property of the write function, not of OpenThread.

*Mitigation:* treat short writes as normal, apply backpressure rather than blind
retry, and carry a watchdog that can recover a wedged TX path from firmware.

**Silent data loss on host stall.** If the host stops draining, the firmware does not
block. It waits 50 ms, then discards bytes and continues. Confirmed by an Espressif
maintainer on issue #11192. This is a data-loss mechanism, not a throttle.

*Mitigation:* resync marker, sequence numbers, large host-side buffers.

**Wi-Fi promiscuous is lossy and expensive.** Espressif's own engineer: promiscuous
mode "is actually not a normal mode, it cost lots of CPU performance". A user measured
~20% loss capturing probe requests. The docs warn sniffer mode has a "great impact" on
throughput, and advise doing no work in the callback.

**802.15.4 timestamp quality is unmeasured** and depends on ISR latency we cannot
predict. Milestone 2 must measure it.

---

## 8. Traps: things that look right and are wrong

Recorded because each was believed during design and disproved by checking.

| Belief | Reality |
|---|---|
| Espressif ship an 802.15.4 sniffer example | They do not. The official route is `ot_rcp` + pyspinel, and **pyspinel was archived read-only in Nov 2024**. |
| Wi-Fi promiscuous gives headers only | It gives full payloads including AMPDU/AMSDU. Only **MIMO frames** are length-only. |
| The C6 has hardware CRC acceleration | **No CRC peripheral exists.** ROM CRC functions are software table lookups. RV32IMAC has no carry-less multiply either. |
| DMA memcpy will speed up the copy path | Measured ~6.4x **slower** than `memcpy`, plus a heap allocation per transfer. A loss at our frame sizes. |
| Both radios hardware-timestamp frames | Only Wi-Fi does. 802.15.4 is a software clock read in the ISR. |
| GPIO14 powers the RF switch, GPIO3 selects | **Reversed.** GPIO3 powers (active low), GPIO14 selects. |
| Power-on default selects the ceramic antenna | The default is *switch unpowered*, reaching the antenna through ~30 dB of leakage. |
| ETM could trigger DMA or timestamps on frame RX | The radio raises **no ETM events at all**. Every such use is impossible. |
| Hardware SHA could replace software CRC | Full DMA setup cost for a 2-block frame, steals a GDMA channel, and emits 8x more bytes onto our actual bottleneck. |
| Console can be separated by per-task stdio redirect | **Picolibc replaced Newlib in v6**; those streams are now global. Use explicit writes. |

---

## 9. Build order

Measurement first. Nobody has published the number that determines the rest of the design.

| # | Milestone | Delivers |
|---|---|---|
| 1 | Transport + throughput benchmark | The unpublished C6 figure, on this board. Sets how aggressive Wi-Fi filtering must be. Exercises the lockup path early. |
| 2 | 802.15.4 → Wireshark, end to end | Strongest mode, lowest risk. Proves the whole chain. Measures ISR jitter. |
| 3 | Wi-Fi leg | Filtering, snaplen, drop accounting under real load. |
| 4 | BLE leg | Advertisement capture with correct PDU typing. |
| 5 | Upstream | PR the advertising-type fix to GhostESP. |

Build ours first, upstream what generalises. Upstream merge latency then cannot block
your own bench.

---

## 10. Open questions requiring hardware

1. Actual sustained USB throughput on this C6. No published figure exists.
2. Whether the gap to the ~1.2 MB/s theoretical bulk ceiling is recoverable via host
   driver choice, larger buffers, or write batching.
3. Whether the Wi-Fi RX timestamp counter shares `esp_timer`'s timebase, and its drift.
   Undocumented; the anchoring design depends on it.
4. 802.15.4 ISR latency and jitter, before and after IRAM placement and priority raise.
   Determines whether those timestamps are usable at all.
5. Real-world antenna delta on this board (community figures disagree: 5 dB vs 10 dB).

---

## 11. Reference projects

Reference only, not dependencies.

| Project | Use | Caution |
|---|---|---|
| Grrtzm/ESP32C6_Wireshark_802.15.4_Sniffer (MIT) | 802.15.4 architecture; confirms TAP link type needs no custom dissector | 3 stars, one day of commits; writes via stdio |
| ESP-IDF `examples/network/simple_sniffer` | Wi-Fi pcap writer reference | No 802.15.4/BLE, no USB streaming, emits no radiotap header (#12320) |
| ESP-IDF `examples/openthread/ot_rcp` | Closest reference for USB framed streaming | Spinel protocol; host tool archived |
| GhostESP | Proof tri-mode firmware is achievable | Pentest tool with attack modules; 802.15.4 never reaches extcap; BLE PDU bug |

---

## 12. Verification

Claims here were checked against primary sources: Espressif datasheets and
documentation, ESP-IDF source at exact tags, the board schematic PDF, the issue
tracker, or the chip itself. Where no data exists, §10 says so rather than estimating.

Three figures are **community-sourced, not vendor-specified**, and are labelled as such
where they appear: the ~30 dB leakage across the unpowered RF switch, the 5–10 dB
external antenna advantage (two sources disagree), and the ~770 kB/s USB throughput
figure (measured on an ESP32-S3, not a C6). Treat all three as indicative and confirm
them on hardware before depending on them.
