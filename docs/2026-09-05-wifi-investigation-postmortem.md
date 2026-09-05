# Post-mortem: "the Wi-Fi radio is dead" — it was not, twice over

**Outcome: Wi-Fi works, and the receiver is also intermittently deaf.**
Promiscuous capture on channel 6 yields ~50 frames/s, management and data,
RSSI −50 to −96 dBm, no drops, decoding correctly in Wireshark. Two real
defects were ours and are fixed. Separately, and not our doing, the Wi-Fi
receiver stops hearing anything for minutes at a time — see "The intermittency"
below, which is the reason single readings kept contradicting each other.

This is kept because the investigation produced several confident wrong
conclusions in a row, and the pattern that produced them is worth not
repeating.

## What was actually wrong

**Defect 1 — the RF switch, in Espressif's examples.** On the XIAO ESP32-C6,
GPIO3 gates the P-FET supplying the FM8625H RF switch and is *pulled up at
reset*. Espressif's examples know nothing about this board and never drive it,
so the switch stays unpowered and the radio reaches the antenna only through
roughly 30 dB of leakage. Every stock example was deaf **by construction**.

**Defect 2 — an uninitialised driver, in our own firmware.**
`sn_radio80211_scan()` called `esp_wifi_set_promiscuous()` and
`esp_wifi_set_mode()` before anything had initialised Wi-Fi. Driver bring-up
lived inside `sn_radio80211_start()`, which the scan path never calls. The
first two calls returned `ESP_ERR_WIFI_NOT_INIT`, the scan reported zero access
points, and **zero was read as "the radio heard nothing" rather than "the radio
was never switched on"**.

Fix: `wifi_init_once()` in `firmware/main/radio80211.c`, called by both paths.
Mode and start stay with each caller, because capture wants `WIFI_MODE_NULL`
and scanning wants `WIFI_MODE_STA`. `main.c` also stops 802.15.4 before any
Wi-Fi work, since one 2.4 GHz front end is shared.

## The three wrong conclusions, in order

1. **"WiFi capture is fine, the band is empty."** Based on a single
   `netsh wlan show networks` returning one 5 GHz network. It returns a
   **cache**. Mathew corrected this; a real rescan showed 11 networks on
   2.4 GHz. The same cache later read "1 network, 5 GHz" for two solid minutes
   before refreshing to eight on 2.4 GHz.

2. **"The Wi-Fi PHY is faulty, claim warranty."** Built on "Espressif's own
   examples fail too", which was Defect 1 and therefore no evidence at all,
   plus a softAP test that inherited the same flaw. Both directions of the link
   looked dead because neither direction had an antenna.

3. **"v6.0.2's PHY blob is broken, v6.1's works."** A single 0-AP reading on
   v6.0.2 against 8 on v6.1. An A/B/A with the same two binaries then gave
   v6.0.2 → 9 APs, v6.1 → 8, v6.0.2 → 8. **It did not reproduce.** One reading
   is not a result.

## What the evidence actually supports

| Build | RF switch | Result |
|---|---|---|
| `wifi/scan`, ESP-IDF v6.1 (phy 345) | powered | 8 APs |
| `wifi/scan`, ESP-IDF v6.0.2 (phy 344) | powered | 9 APs, then 8 |
| `wifi/scan`, either version | **not** powered | 0 APs |
| our firmware, before the fix | powered | `ESP_ERR_WIFI_NOT_INIT`, 0 APs |
| our firmware, after the fix | powered | 11 APs; 731 frames in 15 s on ch 6 |

## The intermittency

Established last, and it reframes everything above. The Wi-Fi receiver on this
board alternates between working and hearing nothing at all, in stretches of
minutes, across power cycles, with **no software change between states**:

| | |
|---|---|
| Espressif's `wifi/scan`, unmodified binary | 9, 8, 8 APs — then 0, 0, 0, 0, 0 on five consecutive boots |
| our firmware, same binary | 665 frames one minute, 0 the next |
| 802.15.4, same board, same antenna, interleaved | worked **every** time |

It is not the band going quiet: during a failing stretch the host still saw a
strong AP on channel 6 at 82 % signal, which is the channel being captured. It
is not our code: Espressif's own binary shows it. It is not the RF switch,
which is explicitly powered and logged, and which 802.15.4 shares. It is not
NVS calibration: a full `erase-flash` does not clear it, and both a
freshly-calibrated and a stored-calibration boot appear in both states.

**The stretches got longer.** Early on it alternated within minutes, which is
where the "minutes at a time" description came from. Later the same day it went
deaf and stayed deaf for over an hour: nine surveys across five minutes found
nothing while the host saw seven 2.4 GHz access points, and that was at the end
of a long unbroken deaf period, not the start of one. So the honest range is
minutes to hours, and the earlier wording understated it.

**One thing has never been tried: removing power.** Every reset in this
investigation has been a soft one -- esptool's `--after hard-reset` toggles the
chip's reset line over USB, and a reflash does the same. Neither drops the
supply to the RF analog domain. The board has also been powered continuously
for many hours, so a thermal or analog-domain latch is consistent with what has
been seen and would not be cleared by anything tried so far. Physically
unplugging the USB-C for a few seconds is the obvious next experiment and costs
nothing.

Two more things it is not, established by the recovery code added afterwards:
a **full driver teardown and rebuild does not clear it** (three consecutive
rebuilds left the callback count at exactly 0), and neither does a full
`erase-flash`. Whatever is wrong sits below `esp_wifi_init`. The rebuild is
kept anyway, with backoff, because it fixes an ordinary driver-level stall and
because the attempt is what makes the condition visible in the counters.

What has not been done is characterising it properly — a scripted N-boot trial
recording calibration mode, temperature and outcome, rather than the ad-hoc
runs that produced this table. Until that exists, "intermittent" is the honest
description and nothing should be reported upstream.

**Practical consequence:** any Wi-Fi test must be repeated before it means
anything, and no offline test may depend on live Wi-Fi traffic. The
`CaptureSession` tests in `host/tests/test_capture.py` are deliberately
hardware-free for this reason.

## The lesson

Each wrong conclusion came from reading **a zero as a measurement**. A zero
from an instrument nobody has proved is switched on measures the instrument,
not the world. And with an intermittent fault in the loop, a single zero
measures the moment, not the system. The 802.15.4 control — 78 frames in 12 s on the same antenna —
felt like it isolated the fault to Wi-Fi, and it did not, because it shared
none of the Wi-Fi bring-up path.

Two habits would have caught all three:

- **Prove the instrument reads non-zero before trusting a zero.** The fix took
  minutes once `ESP_ERR_WIFI_NOT_INIT` was actually printed and read.
- **Repeat before concluding, and alternate.** The A/B/A that demolished
  conclusion 3 took two minutes and should have come before the write-up, not
  after.

Also worth keeping: building with `SDKCONFIG_DEFAULTS` on the command line
overwrites the project's root `sdkconfig`, and a zeroed `wifi_scan_config_t`
means zero dwell per channel — a broken instrument that looks exactly like a
broken radio.
