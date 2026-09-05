# ESP32-C6 Wi-Fi is dead on this board, TX and RX; 802.15.4 on the same antenna works

Status: **investigation record.** Conclusion changed on 2026-09-05 after two
further tests; see "Correction" below. This now reads as a hardware fault, so
the first action is a warranty claim to Seeed, not an ESP-IDF issue.

---

## Finding

On this XIAO ESP32-C6, the 2.4 GHz Wi-Fi radio neither receives nor transmits,
while IEEE 802.15.4 on the same chip, same antenna and same session works
normally. Every driver call returns `ESP_OK`; the failure is entirely silent.

## Hardware and toolchain

| | |
|---|---|
| Board | Seeed Studio XIAO ESP32-C6 |
| Chip | ESP32-C6FH4 (QFN32) rev v0.2, 4 MB embedded flash, 40 MHz crystal |
| eFuse features | `Wi-Fi 6, BT 5 (LE), IEEE802.15.4, Single Core + LP Core, 160MHz` — Wi-Fi is **not** fused off |
| Base MAC | aa:bb:cc:dd:ee:ff (softAP aa:bb:cc:dd:ee:f0) |
| PHY | `phy_version 344,0b4366d,Apr 10 2026` |
| Host | Windows 11, USB-Serial-JTAG on COM3 |

## Evidence

### Receive

Espressif's `examples/wifi/scan`, with only the XIAO RF-switch lines added
(see Correction), on **two ESP-IDF versions**:

| ESP-IDF | `esp_wifi/lib` | Result |
|---|---|---|
| v6.1 (`fff9895c`) | 2026-08-25 | `Total APs scanned = 0` |
| v6.0.2 | 2026-06-19 | `Total APs scanned = 0` |

`libphy.a`, `libnet80211.a` and `libpp.a` are all **different binaries** between
the two versions, so this is not one bad blob shared by both.

`examples/network/simple_sniffer`: 0 packets. Our own promiscuous capture: the
RX callback, counted at its first line before any filtering, fires exactly 0
times.

### Transmit

`examples/wifi/getting_started/softAP` (RF switch added), beaconing as `myssid`
on channel 1, confirmed running from its serial banner. The host machine — with
the board plugged into its own USB port, roughly 10 cm away — never saw it:

```
t=20s  2.4GHz-bssids=8  myssid=absent
t=40s  2.4GHz-bssids=7  myssid=absent
t=60s  2.4GHz-bssids=7  myssid=absent
```

In the same scans the host listed eight 2.4 GHz BSSIDs from neighbours,
including one on channel 1 and two down at 18–20 % signal. A softAP 10 cm from
the adapter should have been the strongest entry in the list.

### The control that makes it Wi-Fi-specific

One firmware, one power-up, one antenna setting:

| Radio | Antenna | Result |
|---|---|---|
| IEEE 802.15.4, promiscuous, channel 25 | internal ceramic | **78 frames in 12 s** |
| Wi-Fi scan | internal ceramic | 0 APs |
| Wi-Fi scan | external u.FL | 0 APs |
| Wi-Fi promiscuous, channels 1/6/11 | either | 0 callbacks |

The antenna, the RF switch and the front end therefore all work.

## Correction, 2026-09-05

An earlier version of this document leaned on "Espressif's own examples fail
too". **That evidence was confounded and the claim was wrong as stated.**

On the XIAO ESP32-C6, GPIO3 gates the P-FET supplying the FM8625H RF switch and
is **pulled up at reset**, so the switch is unpowered on boot and the radio
reaches the antenna only through roughly 30 dB of leakage. Espressif's examples
know nothing about this board and never drive it. A stock example finding
nothing was therefore the expected result and proved nothing.

Both example results above were re-taken with GPIO3 driven low and GPIO14
selecting the ceramic antenna, logged by the firmware at boot
(`XIAO RF switch powered, internal antenna selected`). The results did not
change — which is what makes them worth quoting now.

## Ruled out by measurement

- **ESP-IDF version.** v6.1 and v6.0.2, four different Wi-Fi/PHY blobs.
- **The antenna switch.** Explicitly powered; see Correction.
- **Coexistence with 802.15.4.** Built with `CONFIG_IEEE802154_ENABLED=n`; the
  stock examples contain no 802.15.4 code at all.
- **Missing default event loop.** A real bug in our code, fixed, not the cause.
- **`esp_wifi_start()`**, **`esp_netif_init()`** — tested present and absent.
- **Promiscuous filter mask** — `MASK_ALL` and an explicit `MGMT|DATA|CTRL`.
- **Zero scan dwell** — an explicit 120–400 ms active dwell is used.
- **Stale PHY calibration** — full erase, `falling back to full calibration`,
  mode 2, on both IDF versions.
- **eFuse** — the part reports Wi-Fi 6 present.

## Conclusion and next action

Two ESP-IDF major versions, four distinct blobs, both directions of the link,
and a working 802.15.4 control on the same antenna. That points at the part,
not the framework.

1. **Warranty claim to Seeed** for this board. This is the first action.
2. A second ESP32-C6 would confirm it, and is worth having regardless.
3. An ESP-IDF issue is now only worth filing to ask whether a Wi-Fi PHY
   self-test or RX-path register readback exists, so a dead PHY can be
   distinguished from a software fault without buying hardware. That is a
   question, not a bug report.

## Notes worth keeping

- Building with `SDKCONFIG_DEFAULTS` on the command line overwrites the
  project's root `sdkconfig`; it silently disabled 802.15.4 in what was meant
  to be the full build.
- A zeroed `wifi_scan_config_t` means zero dwell per channel — a broken
  instrument that looks exactly like a broken radio.
- `netsh wlan show networks` returns a **cache**. It showed 1 network on 5 GHz
  for two minutes before refreshing to 8 on 2.4 GHz. Never conclude "the band
  is empty" from one call; poll until it refreshes.
