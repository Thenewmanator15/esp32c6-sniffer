# `esp_ieee802154_disable()` does not release the shared 2.4 GHz front end

**Status:** ready to file, not yet filed. Draft for review before it goes to
Espressif under a real name.

## Summary

On ESP32-C6 with ESP-IDF v6.1, stopping the 802.15.4 radio with
`esp_ieee802154_disable()` leaves the Wi-Fi receiver unable to receive.
`esp_wifi_scan_start()` completes successfully and reports **zero** access
points, indefinitely.

Calling `esp_ieee802154_sleep()` immediately before `esp_ieee802154_disable()`
prevents it. That one call is the entire difference between a working and a
non-working receiver.

The resulting state is **not recoverable in software**. Deep sleep, which
power-gates the RF and modem domains, does not clear it; neither does a
re-flash with a hard reset. Only physically removing power does.

## Environment

| | |
|---|---|
| Chip | ESP32-C6 (Seeed XIAO ESP32-C6) |
| ESP-IDF | v6.1 |
| Radios | 802.15.4 and Wi-Fi, never concurrently |
| Wi-Fi measurement | `esp_wifi_scan_start()`, access points returned |

The board has an RF switch on GPIO3 which must be driven for the antenna to be
connected. It is driven identically in every arm below, so it is not a variable.
802.15.4 shares that switch and keeps working throughout, which is the control
that rules the switch out.

## Expected and actual

**Expected:** after `esp_ieee802154_disable()`, the 2.4 GHz front end is
available to Wi-Fi.

**Actual:** Wi-Fi scans complete and return zero access points. No error is
reported at any layer. The 802.15.4 driver reports success, `esp_wifi_start()`
succeeds, the scan succeeds — and nothing is received.

## Reproduction

Two firmware images differing by one preprocessor guard around a single call:

```c
void sn_radio154_stop(void)
{
    if (!s_running) return;
#if !defined(SN_154_LEGACY_STOP) || !SN_154_LEGACY_STOP
    esp_ieee802154_sleep();          /* present in A, absent in B */
#endif
    esp_ieee802154_disable();
    s_running = false;
}
```

Each trial: power-gate the RF domain, require a Wi-Fi scan to return a non-zero
access-point count (proving the receiver works *before* the treatment), apply
the treatment, then scan again.

Three arms, differing only in how 802.15.4 is left:

* **dirty** — started, then the host disconnects without stopping it. The stop
  path never runs.
* **clean** — started, then stopped via `sn_radio154_stop()`. This is the arm
  that exercises the call under test.
* **idle** — never started.

## Results

Same board, same session, same sequence, same measurement:

| build | dirty | dirty | clean |
|---|---|---|---|
| **A** — `sleep()` then `disable()` | 4 APs | 4 APs | **4 APs** |
| **B** — `disable()` alone | 4 APs | 4 APs | **0 APs** |

Aggregated over the session:

| build | arm | trials | deaf |
|---|---|---|---|
| A (with `sleep`) | clean | 10 | 0 |
| B (without) | clean | 2 | **2** |
| A | dirty | 10 | 0 |
| B | dirty | 4 | 0 |

The **dirty** arm is the internal control and is unaffected in both builds. So
it is not *using* the 802.15.4 radio that breaks Wi-Fi — it is specifically
calling `esp_ieee802154_disable()` without a preceding `esp_ieee802154_sleep()`.

## Controls

* **The receiver is proven working before every trial.** A zero from an
  instrument nobody has proved is switched on measures the instrument.
* **The treatment is proven to have happened**, three ways: every command
  acknowledged, 802.15.4 frames counted actually arriving during the run
  (8–113 per trial), and the driver's own state read back afterwards.
* **802.15.4 continues to work while Wi-Fi is dead** — 13 frames in 8 s on
  channel 15 with the scan simultaneously returning 0. The antenna, the RF
  switch and the shared front end are all demonstrably functional.
* **Arms are interleaved, not blocked**, so a drifting environment cannot
  masquerade as a treatment effect.

## Severity

Higher than it first appears, because of the recovery behaviour. Once
triggered, the following do **not** restore the Wi-Fi receiver:

* deep sleep with an RTC timer wake, which power-gates the RF and modem
  domains — tried four times
* `esp_wifi_deinit()` and a full driver rebuild
* re-flashing the application and hard-resetting via RTS
* `erase-flash`

Only physically removing power does. A product hitting this in the field would
require a user to unplug it.

## What is not claimed

* **n is small on the B side.** Two trials, because each one requires a manual
  power cycle to undo. The split is 2/2 against 0/10, which is unlikely by
  chance but is not a large sample, and more would be better.
* **The mechanism is unknown.** This says one call prevents the fault, not why.
* **Only one board has been tested**, a XIAO ESP32-C6. Whether it reproduces on
  a DevKitC or another C6 module is untested and would strengthen the report
  considerably.
* An earlier version of this investigation attributed the fault to *leaving the
  radio enabled* when the host disconnects. That is the **dirty** arm here, and
  across 14 trials it never reproduced. That claim has been retracted; see
  `2026-09-05-wifi-investigation-postmortem.md`.

## Reproducer

`host/tools/latch_trial.py` in this repository automates the whole thing:

```
python tools/latch_trial.py --port COM3 --arms dirty,dirty,clean --stop-on-deaf
```

Build A is the default. Build B is `idf.py -DSN_MODE=2 -DSN_154_LEGACY_STOP=1 build`.
