# esp32c6-sniffer

A passive tri-radio wireless sniffer on a Seeed Studio XIAO ESP32-C6, streaming into
Wireshark over USB-C.

One radio at a time: **IEEE 802.15.4** (Zigbee/Thread/Matter), **Wi-Fi** (802.11
2.4 GHz), **BLE advertisements**. The board appears in Wireshark as three capture
interfaces; picking one selects the radio.

**Passive capture only.** No transmit, no deauthentication, no injection. Intended for
networks and devices you own or are authorised to test.

## Status

**802.15.4 capture works.** The board appears in Wireshark's interface list and
captures live Zigbee and Thread traffic. BLE is not built yet, and is
deliberately absent from Wireshark rather than present and failing.

**Wi-Fi capture works and appears in Wireshark as a second interface**, with
its own radiotap link type and a 1-14 channel selector. Measured on channel 6:
731 frames in 15 s, management and data, RSSI -50 to -96 dBm, no drops,
decoding as radiotap.

**Caveat, and it is not a small one: this board's Wi-Fi receiver goes deaf, for
anything from minutes to hours.** Espressif's own unmodified scan binary shows
it too -- 9, 8, 8 access points, then zero on five consecutive boots -- while
802.15.4 on the same antenna never fails. A capture that returns nothing is
worth retrying before it means anything.

**The fix is a power cycle, and it is one command:**

```powershell
.\.venv\Scripts\python.exe tools\wifi_survey.py --port COM3 --recover
```

It is a latch in a power domain. No soft reset clears it -- not a driver
rebuild, not a reflash, not a full `erase-flash` -- because none of those
removes power from the RF section. A deep-sleep reset does power-gate it, and
does: measured at the end of an hour-long deaf period, 0 access points before
and 12 after. What sets the latch is still unknown.

Getting here took several confident wrong conclusions, including "the radio is
faulty, claim warranty". Written up in
[docs/2026-09-05-wifi-investigation-postmortem.md](docs/2026-09-05-wifi-investigation-postmortem.md),
because the way the mistakes were made is more useful than the fix.

| Milestone | State |
|---|---|
| 1. USB transport and throughput benchmark | Done, measured at ~810 kB/s |
| 2. IEEE 802.15.4 into Wireshark | Done, all exit criteria met |
| 3. Wi-Fi | Done, in Wireshark; receiver is intermittently deaf, see above |
| 4. BLE advertisements | Not started |

Beyond capture, it also does things other 802.15.4 sniffers do not:

- **Mid-capture channel changes** from a Wireshark toolbar, with no restart.
  Nordic's equivalent has sat unmerged since 2019 and no shipping tool has it.
- **A spectrum survey** using the radio's energy detector, which sees the Wi-Fi
  that overlaps most 802.15.4 channels and is invisible to a packet capture.
- **Drop counters** published by the board, so "did I miss anything" is
  answerable. Measured 0 sequence gaps in 1920 frames.
- **Timestamps good to ~0.5 microseconds**, measured against the standard's
  fixed acknowledgement turnaround.

Read the design first: [docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md](docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md)

It records the verified hardware constraints, the measured transport budget, and
a table of traps: plausible-sounding claims that turned out to be false,
including several that would have silently corrupted or crippled captures.

## Capturing

```powershell
cd firmware
. .\idf-env.ps1
idf.py -DSN_MODE=2 build     # 2 = capture; 0 = conformance tests, 1 = benchmark
.\flash.ps1 -Port COM3
cd ..
.\extcap\install.ps1
```

Flash and install together. The two halves share a wire format, and the host
checks the board's reported firmware version when a capture opens: a mismatch
stops with a message naming both versions rather than decoding older metadata
into confident nonsense.

Restart Wireshark. Both interfaces appear on the welcome screen, with channel
and antenna selectable in their options. Zigbee commonly uses channels 11, 15,
20 and 25; Thread uses anything from 11 to 26.

The sniffer is passive, so it only shows traffic that already exists. If a
channel looks empty, it probably is -- though on Wi-Fi, check the toolbar log
before believing it, because this board's receiver goes deaf for minutes at a
time and the log says when that is happening.

### Wi-Fi options

The Wi-Fi interface has three settings the 802.15.4 one does not need, because
a busy 802.11 channel produces roughly twenty-five times what the USB link
carries. They are throughput controls, not preferences.

| Option | Default | What it does |
|---|---|---|
| Snapshot length | 256 B | Bytes kept per frame. What is cut is encrypted payload; the headers worth having are at the front. Truncation is declared in the pcap, so Wireshark marks frames sliced rather than malformed. |
| Frame types | Management and data | Control frames are the most numerous and least informative. Dropping them buys link budget cheaply. |
| Channel hop | Off | Sweeps 1/6/11 or all of 1-13 at a chosen dwell. Each frame carries its own channel in radiotap, so a hopped capture stays self-describing. |

Hopping trades completeness for coverage: you will miss whatever arrives while
the radio is on another channel. A beacon interval is about 100 ms, so a dwell
below roughly 300 ms starts losing beacons from the very networks you are
trying to find.

## Finding the networks

Don't guess at channels. The survey measures both halves of the question:

```powershell
cd host
.\.venv\Scripts\python.exe tools\survey.py --port COM3
```

Energy detection sees anything radiating, including the Wi-Fi that overlaps
most 802.15.4 channels and is invisible to a packet capture. Traffic counting
sees decoded frames. A channel can be electrically noisy and carry no 802.15.4
at all, or be quiet and carry a network talking softly, so read them together.

`tools/spectrum.py` runs the energy half alone and faster.
`tools/antenna_compare.py` measures the two antennas against the same traffic.

For Wi-Fi, `tools/wifi_survey.py` asks the receiver what it can identify rather
than measuring energy, and prints access points with their channel, signal,
security and the 802.15.4 channels each one overlaps:

```powershell
.\.venv\Scripts\python.exe tools\wifi_survey.py --port COM3 --repeat 3
```

Use `--repeat` and mean it. This board's Wi-Fi receiver goes deaf for minutes at
a time, so an empty result is not evidence of an empty band. `spectrum.py` uses
the 802.15.4 radio and keeps working when Wi-Fi does not, which makes it a
useful second opinion.

## What you will and will not see

Everything the radio delivers is captured, and every frame is dissected as far
as it can be. Verified over a 90 s capture: 87 frames, zero dropped in the
receive interrupt, zero refused by the link, zero buffer overruns, zero
sequence gaps, and **zero data frames left stuck at the MAC layer**.

Two genuine limits, neither fixable in software here:

**Frames that fail their checksum never arrive.** The ESP-IDF 802.15.4 driver
exposes only a receive-done callback, with no failure equivalent, so corrupt
frames are discarded in hardware before we could see them. Some sniffers show
them; this one cannot.

**Payloads are encrypted.** Zigbee and Thread both encrypt above the MAC layer,
so you see frame structure, addresses and routing but not contents. Wireshark
reports this honestly as "Encrypted Payload" and "No encryption key set".

### Decrypting your own network

`install.ps1` does not touch keys, but the project adds the well-known default
Zigbee Trust Center link key to `%APPDATA%\Wireshark\zigbee_pc_keys`. That key
is public and ships with every Zigbee analyser. It does **not** decrypt
arbitrary traffic: it only lets Wireshark read the key-transport message sent
when a device joins, and derive that network's key from it.

To read your own Zigbee network, start a capture on its channel and put a
device into pairing mode. Wireshark picks up the network key from the join and
decrypts from then on. For a network whose key you already know, add it to that
file directly.

### Matter and Thread

Matter over Thread is already captured: those frames arrive and Wireshark
identifies them. Reading them needs your Thread network key, because Thread
encrypts at the MAC layer.

```powershell
cd host
.\.venv\Scripts\python.exe tools	hread_key.py --key <32 hex chars>
```

The key comes from your border router, and only for a network you control.
Home Assistant exposes it under Settings, Devices & Services, Thread. Apple's
Home app can share Thread credentials to a Mac. An OpenThread border router
answers `ot-ctl networkkey`.

With it installed, frames resolve through 6LoWPAN and IPv6 to UDP, and Matter
traffic to its message layer: which node talks to which, session identifiers,
counters, acknowledgements. Wireshark has dissectors for Matter, its Bluetooth
transport and its advertising data built in.

**The Matter payload itself stays encrypted.** It is protected by session keys
negotiated during commissioning, and Wireshark's built-in Matter dissector has
no key table at all, so there is nowhere to supply them. A separate
experimental plugin from the Matter project can decrypt, but it is Linux-only
and built for Wireshark 3.6. That is a real ceiling, not a configuration
problem.

Commissioning itself happens over Bluetooth before a device joins Thread, and
inside a connection, so this chip cannot capture it at all.

## Honest capability ceilings

| Radio | What you actually get |
|---|---|
| 802.15.4 | Strong. Full promiscuous capture with RSSI, LQI and channel. |
| Wi-Fi | Good. Full payloads except MIMO frames. 2.4 GHz only. Encrypted payloads stay encrypted. |
| BLE | Weak. Advertisements only. It cannot follow connections; this is a scanner, not a link-layer sniffer. |

The three radios share one RF front end and **cannot** capture simultaneously.

## Prerequisites

- A Seeed Studio XIAO ESP32-C6.
- **ESP-IDF v6.1**, installed at `H:\dev\tools\.espressif\v6.1\esp-idf` with tools
  under `H:\dev\tools\.espressif`, matching the `IDF_TOOLS_PATH` that
  `H:\dev\setup-caches.ps1` sets.
- Wireshark, for milestone 2 onwards. Npcap is **not** required, because frames
  arrive over USB rather than from a local network adapter.

## Building

```powershell
cd firmware
. .\idf-env.ps1      # dot-sourced, not run
idf.py build
idf.py -p COM3 flash
```

`idf-env.ps1` pins `IDF_TOOLS_PATH` and `IDF_PATH` so a build never depends on
whatever ESP-IDF version happens to be active in the shell.

If flashing fails, hold BOOT, tap RESET, release BOOT, and retry.

## Testing

```powershell
cd host
.\.venv\Scripts\python.exe -m pytest tests\ -q -m "not hardware"   # no board needed
.\.venv\Scripts\python.exe -m pytest tests\ -q -m hardware --port COM3
```

The hardware tests hold the firmware's C frame encoder to byte-identical output
with the Python one, using shared vectors in `host/tests/vectors/golden.json`.
The Python implementation is authoritative; if they disagree, fix the C.
