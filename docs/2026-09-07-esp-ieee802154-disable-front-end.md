# 802.15.4 not stopped cleanly leaves the ESP32-C6 Wi-Fi receiver deaf, past a reset

**Status:** revised 2026-09-27, not yet filed. The first draft said the state
could not be cleared in software. It can, and that changes the report. A
same-day revision then said the deep-sleep power-gate never clears it. It
usually does, and the correction is below. Review again before this goes to
Espressif under a real name.

## Summary

On ESP32-C6 with ESP-IDF v6.1, the Wi-Fi receiver stops receiving after the
802.15.4 radio is left in any state other than slept and then disabled.
`esp_wifi_scan_start()` completes successfully and reports **zero** access
points. There are two ways to get there:

1. **Not stopping 802.15.4 at all.** The chip resets while 802.15.4 is
   receiving. Here the reset comes from the host reopening the USB serial port.
   Wi-Fi was deaf afterwards **every time: 18 trials** over 2026-09-26 and 27.
2. **Stopping it with `esp_ieee802154_disable()` alone**, without
   `esp_ieee802154_sleep()` first. Wi-Fi was deaf **6 times in 6**, against 0
   in 10 with the sleep.

The state survives a CPU reset, a reflash, and in one case an hour's wait. The
deep-sleep power-gate of the RF and modem domains usually clears it, but not
always. Two episodes of case 1 stayed deaf through 16 power-gates between
them, and on 2026-09-07 case 2 needed the board unplugged.

It **is** cleared in software, at once, by enabling 802.15.4 and stopping it
with `esp_ieee802154_sleep()` then `esp_ieee802154_disable()`. That has worked
on every episode of both cases it was tried on, including one the power-gate
had not cleared, with no time spent receiving. Enabling it and stopping it
*without* the sleep does not clear it. So the sleep call is the fix and its
absence is the fault: something in the 802.15.4 sleep path hands the shared
front end back.

## Environment

| | |
|---|---|
| Chip | ESP32-C6 (Seeed XIAO ESP32-C6) |
| ESP-IDF | v6.1 |
| Radios | 802.15.4 and Wi-Fi, never concurrently |
| Wi-Fi measurement | `esp_wifi_scan_start()`, access points returned |

The board has an RF switch on GPIO3, which must be driven for the antenna to be
connected. Every arm below drives it the same way, so it is not a variable.
802.15.4 shares that switch and keeps working throughout, which is the control
that rules the switch out.

## Expected and actual

**Expected:** once 802.15.4 is no longer running, whether it was disabled or
the chip was reset, the 2.4 GHz front end is available to Wi-Fi.

**Actual:** Wi-Fi scans complete and return zero access points, and no layer
reports an error. `esp_wifi_start()` succeeds, the scan succeeds, and nothing
is received.

## Reproduction

Starting 802.15.4 is `esp_ieee802154_enable()`, promiscuous mode, then
`esp_ieee802154_receive()`. The stop, with the single call under test in case 2:

```c
void sn_radio154_stop(void)
{
    if (!s_running) return;
#if !defined(SN_154_LEGACY_STOP) || !SN_154_LEGACY_STOP
    esp_ieee802154_sleep();          /* present normally, absent in build B */
#endif
    esp_ieee802154_disable();
    s_running = false;
}
```

Each trial first proves the receiver works with a Wi-Fi scan that must return
a non-zero count. Only then is the treatment applied, followed by another scan
with nothing in between that could cure it.

The three arms differ only in how 802.15.4 is left:

* **dirty** is case 1: started, then the host disconnects without stopping it,
  so the stop path never runs. Reopening the port resets the chip.
* **clean** is case 2 in build B: started, then stopped via
  `sn_radio154_stop()`.
* **idle**: never started.

## Results

### Case 1: not stopped

| | result |
|---|---|
| dirty arm | Wi-Fi deaf **18 times in 18**, on the 2026-09-07 firmware and the 2026-09-27 one |
| deep-sleep power-gate, 1 s timer wake | cured **9 episodes in 9**, one power-gate each, on 2026-09-27 afternoon; **2 episodes** stayed deaf through 16 attempts between them (2026-09-26, 2026-09-27 morning) |
| waiting, one scan a minute | one of those two was still deaf after 60 minutes |
| enable 802.15.4, then `sleep()` and `disable()` | cured **every episode it was tried on**, 11 of them, including that one |
| the same, with 0, 1 or 5 s receiving in between | cured at every dwell, including 0 s |

### Case 2: disable without sleep

| | result |
|---|---|
| clean arm, build A (`sleep()` then `disable()`) | deaf **0 times in 10** (2026-09-07) |
| clean arm, build B (`disable()` alone) | deaf **6 times in 6** (2 on 2026-09-07, 4 on 2026-09-27) |
| reset, or reflash to build A | not cured, 2 of 2 |
| enable and `disable()` again, still without `sleep()` | not cured, 1 of 1 |
| enable, then `sleep()` and `disable()` (build A) | **cured, 2 of 2** |
| deep-sleep power-gate | cured 2 of 2 on 2026-09-27; did not on 2026-09-07, when the board had to be unplugged |

## Controls

* **The receiver is proven working before every trial.** A zero from an
  instrument nobody has proved is switched on measures the instrument.
* **The treatment is proven to have happened**, three ways:
  - every command was acknowledged;
  - 802.15.4 frames were counted arriving during the run, 8 to 113 per trial;
  - the firmware's own record read back afterwards. That record is a flag in
    `RTC_NOINIT` memory, set when 802.15.4 starts and cleared by a clean stop.
* **802.15.4 continues to work while Wi-Fi is deaf**: 13 frames in 8 s on
  channel 15, while the scan returned 0 at the same time. So the antenna, the
  RF switch and the shared front end all work.
* **Arms are interleaved, not blocked**, so a drifting environment cannot
  masquerade as a treatment effect.

## Severity

The fault gives no sign. Every call succeeds and the receiver simply hears
nothing. Any product that can be reset while 802.15.4 is running reaches
case 1: a watchdog, a crash or a brown-out would each do it. None of the
obvious recoveries is reliable:

* a CPU reset or a reflash: not once;
* `esp_wifi_deinit()` and a full driver rebuild: not once;
* `erase-flash`: not once;
* waiting: not within an hour;
* deep sleep with an RTC timer wake: usually, but not always.

The software cure has never failed, but nothing in the API or its
documentation would lead anyone to it. Our firmware now applies it at boot
whenever its flag says 802.15.4 was left running. Measured: three dirty
trials, each back to 8 access points and 699 to 817 Wi-Fi frames in 8 s at
the next boot, with no other recovery. That works around the problem; it is
not a fix.

## What is not claimed

* **The mechanism is unknown.** This says which calls cause and cure the state,
  not what the state is. The pattern is that the 802.15.4 sleep path clears it
  and the power-gate only sometimes does. That suggests coexistence or PHY
  state held outside the gated domains, or restored into them.
* **Why the power-gate sometimes fails is unknown.** Its two failures on case 1
  were each the first trial of a scripted run. Repeating that run's sequence
  did not reproduce them.
* **Only one board has been tested**, a XIAO ESP32-C6. Whether it reproduces on
  a DevKitC or another C6 module is untested, and a second board would
  strengthen the report considerably.
* **An earlier replication found no effect for case 1**: 2026-09-07, 14 dirty
  trials, all healthy. Its measurement went through a recovery that
  power-gated the board whenever the flag was set, which the dirty arm always
  sets. Rerunning that firmware and tool on 2026-09-27 showed the same null
  result, 5 of 5. The same firmware measured with no recovery went deaf 4
  times in 4, and one power-gate cured each. So those trials were cured before
  they were measured.

## Reproducer

`host/tools/latch_trial.py` in this repository automates the trial. Our
firmware now cures case 1 at boot, and the trial connects to the board and so
boots it, which would cure every dirty trial before it is measured. Build
without that cure to measure it:

```
idf.py -DSN_MODE=2 -DSN_154_NO_BOOT_HANDBACK=1 build
python tools/latch_trial.py --port COM3 --arms dirty,dirty,clean --stop-on-deaf
```

On a standard build, the trial reports each dirty trial as INVALID for this
reason. Build B, for case 2, adds `-DSN_154_LEGACY_STOP=1`. Neither build is
for shipping.
