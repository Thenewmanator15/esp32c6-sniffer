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

/* STATUS: the Wi-Fi receiver hears nothing on this board. Not our bug.
 *
 * Isolated as far as it can be from here:
 *   - 802.15.4 captures thousands of frames losslessly through the SAME
 *     antenna and front end, so the RF path and the antenna switch are fine.
 *   - A Wi-Fi scan finds 0 access points while the host sees 11 on 2.4 GHz.
 *     Verified with explicit 120-400 ms dwell times, since a zeroed
 *     wifi_scan_config_t means zero dwell and would find nothing regardless.
 *   - Promiscuous capture delivers 0 frames on channels 1, 6 and 11, all
 *     confirmed occupied. A counter at the very top of the callback, before
 *     any filtering, stays at exactly 0.
 *   - ESP-IDF's own simple_sniffer example, unmodified, captures 0 packets on
 *     the same board. That rules out this code.
 *   - Every driver call returns ESP_OK. The failure is silent.
 *
 * Eliminated by measurement: missing event loop (a real bug, fixed, but not
 * the cause), calling esp_wifi_start, not calling it, coexistence with
 * 802.15.4 (built with CONFIG_IEEE802154_ENABLED=n and still zero), missing
 * esp_netif_init, and an explicit filter mask instead of all-ones.
 *
 * Remaining candidates, untested: a Wi-Fi PHY or calibration fault specific to
 * this chip revision, or an ESP-IDF v6.1 regression on the C6. Worth reporting
 * upstream, since it reproduces with Espressif's own example.
 *
 * sn_radio80211_scan() exists as the discriminator that established this and
 * is worth keeping. */
