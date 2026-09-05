# Draft upstream report: ESP32-C6 Wi-Fi receiver finds nothing, 802.15.4 on the same board works

Status: **draft, not submitted.** Target: `espressif/esp-idf` issues.

Prepared 2026-09-05. Submit only on Mathew's say-so.

---

## Title

ESP32-C6: Wi-Fi RX finds nothing (scan returns 0 APs, promiscuous callback never
fires) while 802.15.4 on the same board and antenna receives normally — v6.1

## Environment

| | |
|---|---|
| ESP-IDF | v6.1, commit `fff9895c` (`components/esp_wifi/lib` at the same commit, 2026-08-25) |
| Target | esp32c6 |
| Chip | ESP32-C6FH4 (QFN32) rev v0.2, 4 MB embedded flash, 40 MHz crystal |
| eFuse features | `Wi-Fi 6, BT 5 (LE), IEEE802.15.4, Single Core + LP Core, 160MHz` — Wi-Fi is **not** disabled in eFuse |
| Board | Seeed Studio XIAO ESP32-C6 |
| Host | Windows 11, USB-Serial-JTAG on COM3 |
| Base MAC | aa:bb:cc:dd:ee:ff |

## Summary

On this board the Wi-Fi receiver reports success at every API call and receives
nothing at all. `esp_wifi_scan_start()` completes and
`esp_wifi_scan_get_ap_num()` returns 0; in promiscuous mode the RX callback is
never invoked once (counted at the top of the callback before any filtering).

This is not a quiet band and not an antenna fault, because **802.15.4 receives
normally on the same board, the same antenna and in the same session.**

## Reproducer (Espressif's own examples, unmodified)

`examples/wifi/scan`, built and flashed with no source changes:

```
I (2839) scan: Max AP number ap_info can hold = 10
I (2839) scan: Total APs scanned = 0, actual AP number ap_info holds = 0
I (2839) main_task: Returned from app_main()
```

`examples/network/simple_sniffer`, unmodified: **0 packets captured.**

At the same time and place, the host machine's own Wi-Fi adapter sees **11
networks on 2.4 GHz**, two of them on channel 6.

## Control that makes this specific to Wi-Fi

One firmware, one power-up, one antenna setting, switching only the radio:

| Radio | Antenna | Result |
|---|---|---|
| IEEE 802.15.4, promiscuous, channel 25 | internal ceramic | **78 frames in 12 s** |
| Wi-Fi scan (STA, active, 120–400 ms dwell) | internal ceramic | 0 APs |
| Wi-Fi scan | external u.FL | 0 APs |
| Wi-Fi promiscuous, channels 1/6/11 | either | callback count exactly 0 |

The 2.4 GHz front end, the antenna switch and the RF path are therefore all
working. Only the Wi-Fi receiver is deaf.

## Ruled out by measurement, not by argument

- **Coexistence with 802.15.4.** Rebuilt with `CONFIG_IEEE802154_ENABLED=n`, so
  the component is not linked at all. Wi-Fi still found 0 APs. The `wifi/scan`
  example likewise contains no 802.15.4 code.
- **Missing default event loop.** `esp_event_loop_create_default()` was genuinely
  missing in our code and is now called (without it the driver logs
  `failed to post WiFi event ... ret=259`). Fixing it changed nothing.
- **`esp_wifi_start()`.** Tested both called and omitted.
- **`esp_netif_init()`.** Tested both ways.
- **Promiscuous filter mask.** Tested `WIFI_PROMIS_FILTER_MASK_ALL` and an
  explicit `MGMT|DATA|CTRL` union.
- **Zero scan dwell.** A zeroed `wifi_scan_config_t` means zero ms per channel;
  the numbers above use an explicit 120–400 ms active dwell.
- **Stale PHY calibration.** Full chip erase forced a fresh calibration
  (`falling back to full calibration`, mode 2). No change.
- **Antenna selection.** GPIO3 driven low to power the RF switch, GPIO14 tested
  in both positions.

Every driver call returns `ESP_OK` throughout. The failure is silent.

## What we are asking

Is this a known ESP32-C6 Wi-Fi RX regression in v6.1, or does it indicate a
part-specific PHY fault? A GitHub issue search found no matching report.

If the latter, a way to distinguish the two from software (a PHY self-test, an
RX-path register readback, a raw RSSI floor read) would be far more useful than
buying a second board to bisect.

## Local notes, not for upstream

- Only a second ESP32-C6 can currently separate "this chip" from "this
  framework version". We have one board.
- Two traps that cost time here and are worth remembering: building with
  `SDKCONFIG_DEFAULTS` on the command line overwrites the project's root
  `sdkconfig`, which silently disabled 802.15.4 in what was meant to be the
  full build; and a zeroed `wifi_scan_config_t` is a broken instrument that
  looks exactly like a broken radio.
