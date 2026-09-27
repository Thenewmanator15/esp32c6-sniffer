# Post-mortem: "the Wi-Fi radio is dead" — it was not, twice over

**Outcome: Wi-Fi works, and the deafness has a root cause and a one-command
fix.** Promiscuous capture on channel 6 yields ~55 frames/s, management and
data, RSSI −50 to −96 dBm, correct rates and modulation, 6 malformed frames in
1100. Two real defects were ours and are fixed. The third problem was not ours:
the receiver latches deaf. That day a power-gate of the RF domain cleared it —
0 access points before a deep-sleep reset, 12 after; see "Root cause" below.
That latch is why single readings kept contradicting each other all day.
(Corrected 2026-09-27: the deafness that leaving 802.15.4 running causes is
*not* cleared by a power-gate, 0 times in 16, and a clean 802.15.4 start and
stop clears it every time. See the correction of that date.)

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

(2026-09-27: true of that day's deafness, whose cause was never pinned down.
The deafness 802.15.4 left running causes is different: a power-gate does not
clear it, and a clean 802.15.4 start and stop does. See the correction of that
date below.)

It also explains why the "recoveries" counter climbed while frames stayed at
zero: rebuilding the driver cannot clear a latch below it.

The workaround is `SN_CMD_RADIO_POWER_CYCLE`, exposed as
`tools/wifi_survey.py --recover`. It is a command rather than part of the
automatic stall recovery because it resets the board, which would end a running
Wireshark capture without warning; the capture log says what to run instead.

**What sets it — RETRACTED 2026-09-07, and the retraction withdrawn
2026-09-26:** see "The retraction was confounded" below. The paragraph below
stood for two days and was then taken not to replicate. It is kept, struck through, because the way it failed is
the same lesson this document is about.

> ~~**What sets it, resolved.** Not time, not heat: leaving the 802.15.4 radio
> enabled when the host disconnects. Three arms, each starting from a working
> Wi-Fi receiver, 25 seconds of activity each:~~
>
> | arm | Wi-Fi frames before | after |
> |---|---|---|
> | ~~802.15.4 left running~~ | ~~389~~ | ~~**0**~~ |
> | ~~802.15.4 stopped properly first~~ | ~~564~~ | ~~449~~ |
> | ~~idle~~ | ~~425~~ | ~~539~~ |
>
> ~~Reproduced on demand.~~

That table is **one trial per arm**, and this document's own closing lesson is
"repeat before concluding, and alternate". It did neither. `tools/latch_trial.py`
now does, and the effect is not there:

| measure | arm | n | deaf | counts after treatment |
|---|---|---|---|---|
| access points | dirty | 5 | 0 | 4, 4, 4, 4, 4 |
| access points | clean | 5 | 0 | 4, 4, 4, 4, 4 |
| access points | idle | 5 | 0 | 4, 4, 4, 4, 4 |
| Wi-Fi frames | dirty | 3 | 0 | 596, 645, 587 |
| Wi-Fi frames | clean | 3 | 0 | 634, 671, 605 |
| Wi-Fi frames | idle | 3 | 0 | 567, 440, 529 |

**24 trials, two different instruments, no effect.** The frame measure is the
one the retracted table used, so this is a like-for-like replication and not a
change of subject.

The treatment is not in doubt, which is what makes the null result mean
something. Every dirty trial was verified three ways: every command
acknowledged, 8 to 113 802.15.4 frames actually counted arriving during the
dwell, and the board's own `RADIO_DIRTY` flag reading back **dirty** in 8 of 8
dirty trials and **clean** in all 16 others. The front end was, by the
firmware's own account, left owned — and Wi-Fi worked anyway.

Two earlier versions of that trial produced clean-looking null results that were
worthless, and both are worth recording:

- The first acknowledged **not one command**. `START` carries the channel as its
  value for 802.15.4, and passing 0 is refused as `BAD_VALUE`. The radio never
  started, so all three arms were the idle arm — and the table looked perfectly
  reasonable. This is the same error as reading a zero from an instrument nobody
  proved was switched on, applied to the *treatment* rather than the
  measurement.
- The second crashed on a serial handle that had gone stale across a deep-sleep
  reset.

**What this does and does not overturn.** It does not say the deafness never
happened; the original observations were real observations of something. It says
the stated *cause* does not survive replication, so the mechanism is unknown
again. Every trial here starts from a power-gate and runs a 25-second arm, so a
trigger needing long uptime, heat, or a particular sequence would be missed.

**Nothing has been reported upstream, and on this evidence nothing should be.**
A vendor report resting on n=1 that fails at n=24 would be worse than silence.
(Written before the correction below: the n=24 did not test the dirty arm.)

**The workaround stays.** `esp_ieee802154_sleep()` before `disable()`, the
`RADIO_DIRTY` flag, `ensure_wifi_ready()` and `SN_CMD_RADIO_POWER_CYCLE` all
remain, because they are cheap, they are harmless, and something did produce
those original zeros. What is removed is the claim to know why.
`SN_154_LEGACY_STOP` builds the firmware without the sleep, so if the effect is
ever reproduced the single API call can be isolated in an A/B.

**The retraction was confounded — 2026-09-26.** Both of the trial's measures
reached the board through the host's recovery: `scan_access_points()` and
`CaptureSession` call `ensure_wifi_ready()`, which power-cycles the board when
`RADIO_DIRTY` is set, and the dirty arm is the arm that sets it. The flag
reading back **dirty** in 8 of 8 dirty trials, recorded above as proof the
treatment happened, is also what made each measurement power-gate the board
before it looked. "Left owned, and Wi-Fi worked anyway" was the recovery
working. The recovery was in `scan.py` from 2026-09-06, a day before the trial
tool, so no dirty trial in that table was ever measured. The clean and idle
arms, whose flag read clean, were measured as intended. The access-point
counts were also capped at four by a scan bug since fixed -- the board sent
the first four records and dropped the rest -- though a deaf receiver still
reads zero.

The trial now measures with `recover=False`. Run again on 2026-09-26, 23:50:

| arm | access points before | after | after a power-gate |
|---|---|---|---|
| dirty | 7 | **0** | 0 |

Every later trial then failed its baseline: fourteen power-gates in seven
minutes, all deaf. Twenty minutes after the last, with the board reflashed
and used for BLE and 802.15.4 in between but never unplugged, a scan heard 9.

One trial is not a rate, and this document's lesson applies to it as much as
to the table it overturns. But the retraction rested on trials that could not
have shown the effect, so it is withdrawn, and the original account is the
best one there is: leaving the 802.15.4 radio running when the host goes can
deafen the Wi-Fi receiver -- and that deafness, unlike the one this document
opens with, did not clear with a power-gate. More trials need `--stop-on-deaf`
and patience, since a deaf trial costs the board until it clears.

**Corrected again — 2026-09-27: the power-gate is not the cure, and a clean
stop is.** More trials, with the trial's own recovery off and each cure
measured separately:

| | result |
|---|---|
| 802.15.4 left running when the host goes | Wi-Fi deaf **8 times in 8** |
| the deep-sleep power-gate | cured it **0 times in 16** |
| waiting, one scan a minute | still deaf after an hour |
| starting 802.15.4 and stopping it cleanly | cured it **8 times in 8**, at once |

The last row held at every dwell tried, 0, 1 and 5 seconds, so receiving is
not what cures it. The 802.15.4 stop path does, which puts the radio to sleep
and then disables it. Three things written above need correcting in its light:

- **"Twenty minutes later it heard 9"** was not the receiver recovering on its
  own. 802.15.4 sanity captures ran in that gap, and each one ended with a
  clean stop. The hour's wait, with nothing else run, did not cure it.
- **"The retraction was confounded"** blamed the replication's null result on
  the recovery power-gating each dirty trial before it was measured. The
  power-gate cures this 0 times in 16, and the recovery at the time was that
  power-gate and nothing more. So that explanation fails too, and why those
  eight dirty trials read healthy is unknown. Only the result above survives:
  the dirty arm, measured with nothing in the way, went deaf 9 times in 9 over
  two days.
- **"Only a power-gate clears"** it, and the automatic power cycle, were right
  for the deafness this document opens with. That one had an unknown cause,
  and on 2026-09-25 it reappeared with the flag reading clear; the power-gate
  cured it again. They were wrong for 802.15.4 left running.

So the recovery changed:

- **The firmware** clears its flag on a clean stop, since that is the cure.
  At boot, if the flag is still set, it starts 802.15.4 and stops it cleanly
  before any command arrives. The board boots whenever a host opens the port,
  so every tool that connects finds Wi-Fi working. Measured: three dirty
  trials, each back to 8 access points and 699 to 817 Wi-Fi frames in 8 s at
  the next connection, with nothing from the host.
- **The host** does the same hand-back when it sees the flag, for older
  firmware. When a capture hears nothing and a scan of the band finds nothing,
  it hands back first and power-cycles only if that fails.
- **`latch_trial.py`** now scores a dirty trial as INVALID when its flag reads
  clear. On a standard build the boot cure runs before the trial can measure
  anything. Measuring the latch needs `-DSN_154_NO_BOOT_HANDBACK=1`.

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
connection it can reopen. (The boot cure the firmware has now, from 2026-09-27,
is a different one: a clean 802.15.4 start and stop, which takes milliseconds
and leaves the link alone.)

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

The scripted trial that was missing here now exists as
`tools/latch_trial.py`. It first retracted the trigger, on trials its own
recovery had cured, and measured properly it reproduced it (see above). What still has not been done is a trial long enough to reach
whatever the real trigger is: these arms are 25 seconds from a power-gated
start, and the original deafness appeared during long ad-hoc sessions. Uptime,
temperature and time-to-deafness remain unmeasured. Nothing has been reported
upstream yet; on the corrected evidence a report is back on the table, once
there is more than one trial behind it.

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
