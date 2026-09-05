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

- ESP-IDF **v6.1** (pinned tag). Install via the ESP-IDF Installation Manager:
  `winget install Espressif.EIM` then `eim install -i v6.1`
- Wireshark. Npcap is *not* required; frames arrive over USB, not from a local adapter.
- A Seeed Studio XIAO ESP32-C6.
