#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 2.4 GHz only. The ESP32-C6 has no 5 GHz radio. */
#define SN_80211_CHANNEL_MIN 1
#define SN_80211_CHANNEL_MAX 14

/* Metadata prepended to every captured frame, 12 bytes, little-endian.
 * The host turns this into a radiotap header.
 *
 * We define our own layout rather than shipping Espressif's rx_ctrl struct,
 * deliberately. That struct has two variants in the same header selected by
 * SOC_WIFI_MAC_VERSION_NUM, with different field widths: the C6 uses version 2,
 * where channel is 4 bits, while version 3 gives it 8. Reading it on the host
 * would mean tracking which variant a given chip compiles to. Letting the
 * firmware's compiler pick the right variant and copying the fields out into a
 * fixed layout removes the problem entirely. */
typedef struct __attribute__((packed)) {
    uint8_t channel;
    int8_t rssi_dbm;
    int8_t noise_floor;
    uint8_t flags;
    uint32_t timestamp_us; /* hardware-latched from the radio's own counter */
    uint16_t orig_len;     /* on-air length, so truncation stays visible */
    uint16_t reserved;
} sn_80211_meta_t;

/* Deliver every frame type. Numerically equal to
 * WIFI_PROMIS_FILTER_MASK_ALL, defined here so callers need not pull in
 * esp_wifi.h. Note the field is a PASS mask despite being called a filter:
 * all-ones means deliver everything, not block everything. */
#define SN_80211_FILTER_ALL 0xFFFFFFFFu

#define SN_80211_FLAG_TRUNCATED 0x01u /* payload cut to the snapshot length */
#define SN_80211_FLAG_RX_ERROR  0x02u /* radio reported a reception error */

typedef struct {
    /* Counted at the very top of the callback, before any filtering, so a
     * zero here means the driver never called us at all -- a different
     * problem from us discarding what it delivers. */
    uint32_t callbacks;
    uint32_t skipped_misc;
    uint32_t skipped_zero_len;
    uint32_t frames_captured;
    uint32_t frames_truncated;
    uint32_t isr_queue_full;
    uint32_t link_rejected;
    uint32_t bytes_dropped_by_snaplen;
} sn_80211_stats_t;

/* Starts promiscuous capture.
 *
 * `snaplen` truncates each frame, and doing so is not optional in practice: a
 * busy 802.11 channel produces roughly twenty-five times what the USB link can
 * carry. What gets discarded is the encrypted payload, which is unreadable
 * anyway; the headers that carry the useful information are at the front.
 *
 * `filter_mask` is a wifi_promiscuous_filter_t mask. Note it is a PASS mask
 * despite the name: WIFI_PROMIS_FILTER_MASK_ALL means deliver everything. */
esp_err_t sn_radio80211_start(uint8_t channel, uint16_t snaplen,
                              uint32_t filter_mask);
esp_err_t sn_radio80211_set_channel(uint8_t channel);
void sn_radio80211_stop(void);
uint8_t sn_radio80211_channel(void);
void sn_radio80211_get_stats(sn_80211_stats_t *out);

/* Diagnostic: performs a blocking scan and reports how many access points the
 * radio found. Scanning uses the same receiver as promiscuous capture but a
 * different driver path, so it discriminates between "the radio cannot hear
 * anything" and "promiscuous mode specifically is not delivering". */
esp_err_t sn_radio80211_scan(uint16_t *out_ap_count);

#ifdef __cplusplus
}
#endif

/* STATUS: the Wi-Fi radio on this board is dead in BOTH directions. Not our
 * code, and on the evidence below, not ESP-IDF either.
 *
 * Controlled comparison, one firmware, one session, same antenna:
 *   802.15.4 channel 25, internal antenna  -> 78 frames in 12 s
 *   Wi-Fi scan, internal antenna           -> 0 access points
 *   Wi-Fi scan, external antenna           -> 0 access points
 *   Wi-Fi promiscuous, channels 1/6/11     -> callback fired exactly 0 times
 *
 * Receive, on Espressif's own examples/wifi/scan with only the XIAO RF-switch
 * lines added: "Total APs scanned = 0" on ESP-IDF v6.1 AND on v6.0.2, whose
 * libphy.a, libnet80211.a and libpp.a are all different binaries.
 *
 * Transmit, on their softAP example: the board beacons as myssid on channel 1,
 * confirmed from its own banner, and a host adapter 10 cm away never lists it
 * across repeated scans that do show eight neighbouring 2.4 GHz BSSIDs, two of
 * them at 18-20 % signal.
 *
 * Eliminated by measurement, not argument: the ESP-IDF version (two majors);
 * missing esp_event_loop_create_default (a genuine bug, fixed, not the cause);
 * calling esp_wifi_start; not calling it; coexistence with 802.15.4 (built with
 * the component excluded); missing esp_netif_init; an explicit filter mask
 * instead of all-ones; stale PHY calibration; and both antennas. eFuse reports
 * Wi-Fi 6 present, so the part is not fused off.
 *
 * CORRECTION. This comment previously rested on "ESP-IDF's own simple_sniffer
 * captures 0 packets here too". That was confounded and the claim was wrong:
 * Espressif's examples never drive GPIO3, which is pulled UP at reset and
 * leaves the FM8625H switch unpowered, so any stock example is deaf on this
 * board by construction. Every example result quoted above was re-taken with
 * the switch explicitly powered.
 *
 * Conclusion: a hardware fault in this part's Wi-Fi PHY. Warranty claim first.
 * The full record, with the numbers, is in
 * docs/upstream/2026-09-05-esp32c6-wifi-rx-deaf.md.
 *
 * Two traps that wasted time and are worth knowing. Building with
 * SDKCONFIG_DEFAULTS overwrites the project's root sdkconfig, which silently
 * disabled 802.15.4 in what was supposed to be the full build. A zeroed
 * wifi_scan_config_t means zero dwell per channel, so it finds nothing however
 * loud the air is -- a broken instrument that looks like a broken radio. And
 * netsh wlan show networks returns a CACHE: it read 1 network on 5 GHz for two
 * minutes before refreshing to 8 on 2.4 GHz. */
