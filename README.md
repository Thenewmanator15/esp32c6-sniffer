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
captures live Zigbee and Thread traffic. Wi-Fi and BLE are not built yet, and
are deliberately absent from Wireshark rather than present and failing.

| Milestone | State |
|---|---|
| 1. USB transport and throughput benchmark | Done, measured at ~810 kB/s |
| 2. IEEE 802.15.4 into Wireshark | Done, all exit criteria met |
| 3. Wi-Fi | Not started |
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

Restart Wireshark. The interface appears on the welcome screen, with channel and
antenna selectable in its options. Zigbee commonly uses channels 11, 15, 20 and
25; Thread uses anything from 11 to 26.

The sniffer is passive, so it only shows traffic that already exists. If a
channel looks empty, it probably is.

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
