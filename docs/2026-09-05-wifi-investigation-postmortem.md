# Post-mortem: "the Wi-Fi radio is dead" — it was not, twice over

**Outcome: Wi-Fi works, and the deafness has a root cause and a one-command
fix.** Promiscuous capture on channel 6 yields ~55 frames/s, management and
data, RSSI −50 to −96 dBm, correct rates and modulation, 6 malformed frames in
1100. Two real defects were ours and are fixed. The third problem was not ours:
the receiver latches deaf, and **only power-gating the RF domain clears it** —
0 access points before a deep-sleep reset, 12 after. See "Root cause" below.
That latch is why single readings kept contradicting each other all day.

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
| after a deep-sleep power cycle | **0 access points before, 12 after** |

It is not the band going quiet: during a failing stretch the host still saw a
strong AP on channel 6 at 82 % signal, which is the channel being captured. It
is not our code: Espressif's own binary shows it. It is not the RF switch,
which is explicitly powered and logged, and which 802.15.4 shares. It is not
NVS calibration: a full `erase-flash` does not clear it, and both a
freshly-calibrated and a stored-calibration boot appear in both states.

### Root cause: it is a latch in a power domain

**Found, and it is fixable in software.** A deep-sleep reset power-gates the
modem and RF domains and comes back through a full chip reset. Measured
immediately after nine failed surveys across five minutes, at the end of a deaf
period more than an hour long:

```
before power cycle: access points = 0
sending RADIO_POWER_CYCLE (deep sleep, 1 s)...
after power cycle:  access points = 12
```

That explains everything that did not add up. Every reset tried during the
investigation was a **soft** one -- esptool's reset line, a reflash, a full
`erase-flash`, `esp_wifi_deinit()` and rebuild -- and none of them removes power
from the RF domain. The fault was never in flash, never in NVS calibration,
never in the driver, and never in our code. It sat in analog state that only a
power-gate clears.

It also explains why the "recoveries" counter climbed while frames stayed at
zero: rebuilding the driver cannot clear a latch below it.

The workaround is `SN_CMD_RADIO_POWER_CYCLE`, exposed as
`tools/wifi_survey.py --recover`. It is a command rather than part of the
automatic stall recovery because it resets the board, which would end a running
Wireshark capture without warning; the capture log says what to run instead.

**What sets it, resolved.** Not time, not heat: leaving the 802.15.4 radio
enabled when the host disconnects. Three arms, each starting from a working
Wi-Fi receiver, 25 seconds of activity each:

| arm | Wi-Fi frames before | after |
|---|---|---|
| 802.15.4 left running | 389 | **0** |
| 802.15.4 stopped properly first | 564 | 449 |
| idle | 425 | 539 |

Reproduced on demand. The "hours-long deaf stretches" earlier in the day were
not duration at all -- they were ad-hoc probe scripts that opened the port,
started 802.15.4 and closed without sending STOP, leaving the radio enabled.
Every later Wi-Fi attempt found the front end still owned. The scan binaries
that kept working are the ones that never touch 802.15.4.

Two things had to be right for the fix to work, and each was wrong first:

- The flag has to survive a reset, because **opening the serial port resets the
  chip** -- measured, the since-boot frame counter went 39 to 3 across a
  reopen while advancing 38 over 12 s with the port held open. So the host
  cannot connect to ask a question without destroying the answer.
- `RTC_DATA_ATTR` is not enough. It survives deep sleep but is re-initialised
  from the image on an ordinary reset, which is precisely the reset in
  question; it read back false every time and the recovery never ran.
  `RTC_NOINIT_ATTR` with a magic word is what survives.

Healing automatically at boot was tried and is worse: the board boots when the
host opens the port, so it would deep-sleep immediately and leave the caller
holding a handle to a device that had gone away. The host asks instead, over a
connection it can reopen.

**The stretches got longer.** Early on it alternated within minutes, which is
where the "minutes at a time" description came from. Later the same day it went
deaf and stayed deaf for over an hour: nine surveys across five minutes found
nothing while the host saw seven 2.4 GHz access points, and that was at the end
of a long unbroken deaf period, not the start of one. So the honest range is
minutes to hours, and the earlier wording understated it.

Two more things it is not, established by the recovery code added afterwards:
a **full driver teardown and rebuild does not clear it** (three consecutive
rebuilds left the callback count at exactly 0), and neither does a full
`erase-flash`. Whatever is wrong sits below `esp_wifi_init`. The rebuild is
kept anyway, with backoff, because it fixes an ordinary driver-level stall and
because the attempt is what makes the condition visible in the counters.

What has still not been done is characterising what *sets* the latch — a
scripted trial recording uptime, temperature and time-to-deafness, rather than
the ad-hoc runs that produced this table. The clearing mechanism is now known;
the triggering one is not, so nothing has been reported upstream yet.

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
