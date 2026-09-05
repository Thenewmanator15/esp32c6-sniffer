# esp32c6-sniffer

A passive tri-radio wireless sniffer on a Seeed Studio XIAO ESP32-C6, streaming into
Wireshark over USB-C.

One radio at a time: **IEEE 802.15.4** (Zigbee/Thread/Matter), **Wi-Fi** (802.11
2.4 GHz), **BLE advertisements**. The board appears in Wireshark as three capture
interfaces; picking one selects the radio.

**Passive capture only.** No transmit, no deauthentication, no injection. Intended for
networks and devices you own or are authorised to test.

## Status

Design stage. Nothing is implemented yet.

Read the design first: [docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md](docs/superpowers/specs/2026-09-05-esp32c6-sniffer-design.md)

It records the verified hardware constraints, the transport budget, and a table of
traps — plausible-sounding claims that turned out to be false, including two that
would silently corrupt or cripple captures.

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
