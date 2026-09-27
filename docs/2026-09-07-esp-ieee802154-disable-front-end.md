# 802.15.4 not stopped cleanly leaves the ESP32-C6 Wi-Fi receiver deaf, past a reset and deep sleep

**Status:** revised 2026-09-27, not yet filed. The first draft said the state
could not be cleared in software; it can, and that changes the report. Review
again before it goes to Espressif under a real name.

## Summary

On ESP32-C6 with ESP-IDF v6.1, the Wi-Fi receiver stops receiving after the
802.15.4 radio is left in any state other than slept and then disabled.
`esp_wifi_scan_start()` completes successfully and reports **zero** access
points. There are two ways to get there:

1. **Not stopping 802.15.4 at all.** The chip resets while 802.15.4 is receiving;
   here the reset comes from the host reopening the USB serial port. Wi-Fi was
   deaf afterwards **8 times in 8** (2026-09-27).
2. **Stopping it with `esp_ieee802154_disable()` alone**, without
   `esp_ieee802154_sleep()` first. Wi-Fi was deaf **2 times in 2**, against 0 in
   10 with the sleep (2026-09-07).

The state survives a CPU reset. It also survives deep sleep with an RTC timer
wake, which power-gates the RF and modem domains: **0 cures in 16**. It
survives a reflash, and it was still there after an hour's wait.

It **is** cleared in software, at once, by enabling 802.15.4 and stopping it
with `esp_ieee802154_sleep()` then `esp_ieee802154_disable()`: **8 times in 8**,
with no time spent receiving. So something in the 802.15.4 stop path hands the
shared front end back, and it lives somewhere a power-gate does not reset.

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

Each trial first proves the receiver works: 802.15.4 is started and stopped
cleanly, the RF domain is power-gated, and a Wi-Fi scan must return a non-zero
count. Only then is the treatment applied, followed by another scan.

The three arms differ only in how 802.15.4 is left:

* **dirty** is case 1: started, then the host disconnects without stopping it,
  so the stop path never runs. Reopening the port resets the chip.
* **clean** is case 2 in build B: started, then stopped via
  `sn_radio154_stop()`.
* **idle**: never started.

## Results

### Case 1: not stopped (2026-09-27, measured with no recovery in the path)

| | result |
|---|---|
| dirty arm | Wi-Fi deaf **8 times in 8**: a working baseline before, 0 access points after |
| deep-sleep power-gate, 1 s timer wake | cured it **0 times in 16** |
| waiting, one scan a minute | still deaf after 60 minutes |
| enable 802.15.4, then `sleep()` and `disable()` | cured it **8 times in 8**, at once |
| the same, with 0, 1 or 5 s receiving in between | cured at every dwell, including 0 s |

The trial on 2026-09-26 found the same thing: 7 access points to 0, and the
receiver stayed deaf through fourteen power-gates.

### Case 2: disable without sleep (2026-09-07)

| build | arm | trials | deaf |
|---|---|---|---|
| A, `sleep()` then `disable()` | clean | 10 | 0 |
| B, `disable()` alone | clean | 2 | **2** |

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
nothing. The obvious recoveries do **not** restore it:

* deep sleep with an RTC timer wake, which power-gates the RF and modem
  domains (0 in 16);
* `esp_wifi_deinit()` and a full driver rebuild;
* re-flashing the application and hard-resetting via RTS;
* `erase-flash`;
* an hour's wait.

The software cure works, but nothing in the API or its documentation would
lead anyone to it. Any product that can be reset while 802.15.4 is running
reaches case 1: a watchdog, a crash or a brown-out would each do it. Such a
product loses Wi-Fi until its firmware happens to start and stop 802.15.4
cleanly.

Our firmware now does exactly that at boot whenever its flag says 802.15.4 was
left running. Measured: three dirty trials, each back to 8 access points and
699 to 817 Wi-Fi frames in 8 s at the next boot, with no other recovery. That
works around the problem; it is not a fix.

## What is not claimed

* **The mechanism is unknown.** This says which calls cause and cure the state,
  not what the state is. That it survives a power-gate of the RF and modem
  domains suggests it is held elsewhere, perhaps in coexistence or PHY state
  that the 802.15.4 sleep path resets.
* **n is small for case 2**: two trials, from before the software cure was
  known, when each deaf trial needed a manual power cycle to undo. Whether the
  same cure clears case 2 has not been tested.
* **Only one board has been tested**, a XIAO ESP32-C6. Whether it reproduces on
  a DevKitC or another C6 module is untested, and a second board would
  strengthen the report considerably.
* **Case 1 has not always reproduced.** On 2026-09-07, 14 dirty trials (10 in
  build A and 4 in B) read healthy. Those scans went through the host's
  recovery at the time, which was the deep-sleep power-gate. They were later
  written off as cured before they were measured. That no longer holds, since
  the power-gate cures case 1 0 times in 16. Why those trials did not latch is
  unknown. Something may have differed between the two days that was not
  recorded.

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
reason. Build B, for case 2, is `idf.py -DSN_MODE=2 -DSN_154_LEGACY_STOP=1
build`. Neither build is for shipping.
