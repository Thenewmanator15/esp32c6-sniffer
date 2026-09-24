# Count the 802.15.4 frames the nRF54L15 discards as corrupt

## Why

Neither board can capture a frame that fails its checksum: both drivers drop
it before the firmware sees anything, and the README says so. What the nRF54L15
*can* do is count them. Zephyr's nRF 802.15.4 driver reports each failed
reception to a registered event handler, with the reason
`IEEE802154_RX_FAIL_INVALID_FCS` for a bad checksum
(`drivers/ieee802154/ieee802154_nrf5.c`, NCS v3.4.0). A count turns "frames lost
to interference or range" from invisible into a number beside the drop
counters. The contents of those frames stay out of reach: the driver hands over
the failure, not the bytes.

## What changes

### nRF54L15 firmware (`nrf54l15-sniffer`)

- `src/radio154.c`: when the radio starts, register an event handler through
  `api->configure(radio, IEEE802154_CONFIG_EVENT_HANDLER, ...)`. It counts
  `IEEE802154_EVENT_RX_FAILED` events whose reason is
  `IEEE802154_RX_FAIL_INVALID_FCS`, atomically, since the driver may call it
  from interrupt context. Other reasons (not received, address filtered) are
  not counted: the first is the radio's ordinary listening, the second cannot
  happen in promiscuous mode. The counter resets when the radio starts, as
  the captured counter does, and is read with `sn_radio154_fcs_failed()`.
- `src/main.c`: `struct sn_stats_full` gains `uint32_t fcs_failed` as its last
  member, after the BLE block. Appended, never inserted, because the host reads
  the STATS frame by position and tells tiers apart by length.
- `SN_FIRMWARE_VERSION` goes from 3 to 4 (agreed with the other session working
  in this repository on 2026-09-24; it takes the next free number after).

### Host (`esp32c6-sniffer`)

- `capture.py`: a new tier `_STATS_V6`, 33 counters, first in `_STATS_TIERS`.
  `CaptureStats.fw_fcs_failed` is `None` unless the board sent the counter, so
  "not measured" stays distinct from 0. The ESP32-C6 does not send it, and its
  firmware is unchanged. The count is taken during 802.15.4 captures only.
- `EXPECTED_FIRMWARE_VERSIONS["nrf54l15"]` becomes 4.
- The toolbar's once-a-second line adds `, N corrupt frames discarded by the
  radio` when the count is known. It is **not** loss in the capture's own sense
  and does not enter `lossless` or the pcapng drop count: those count frames
  the board received and failed to deliver, and a corrupt frame was never
  received.
- `pcapng.write_statistics` gains an optional `comment`. The extcap passes
  `"<N> frames failed their FCS at the radio and were not captured"` when the
  count is known, so a capture file read back later still says so.
- `test_stats_layout.py` checks that the nRF's `sn_stats_full` ends with
  `fcs_failed` and that `_STATS_V6` is exactly one counter wider than
  `_STATS_V5`, reading the struct out of `main.c` as it already reads headers.

## Tests

- Host: a 33-counter STATS payload during an 802.15.4 capture sets
  `fw_fcs_failed`; a 32-counter one leaves it `None`; a BLE capture ignores it;
  `lossless` is unaffected; the statistics block carries the comment only
  when the count is known.
- Layout: as above.
- On air: the XIAO running the new firmware captures the Thread network on
  channel 15 for 60 s and reports a count; the ESP32-C6 on the same channel
  shows no count ("not measured"). The figure is reported as measured, not as
  a property of the network.

## Out of scope

- Capturing the corrupt frames' bytes. The driver does not hand them over; that
  would need a raw radio driver, the same work as following BLE connections.
- Per-channel counts during channel hopping. The counter is per capture.
