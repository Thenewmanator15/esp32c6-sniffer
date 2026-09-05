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

#ifdef __cplusplus
}
#endif

/* STATUS: NOT WORKING as of 2026-09-05.
 *
 * The driver initialises, logs ic_enable_sniffer, accepts a channel, and then
 * never invokes promiscuous_cb. Instrumented with a counter incremented at the
 * very top of the callback before any filtering: it stays at exactly 0.
 *
 * Eliminated so far, each by measurement rather than reasoning:
 *   - missing esp_event_loop_create_default(): was genuinely absent and logged
 *     "failed to post WiFi event ret=259"; adding it changed nothing
 *   - calling esp_wifi_start(): no change
 *   - NOT calling it, matching ESP-IDF's simple_sniffer example: no change
 *   - coexistence with 802.15.4 (ESP-IDF #18838): disproved by building with
 *     CONFIG_IEEE802154_ENABLED=n, which still gives cb=0
 *   - missing esp_netif_init(), and an explicit MGMT|DATA|CTRL filter mask
 *     instead of all-ones: no change
 *
 * Next step is a proper control: build ESP-IDF's own simple_sniffer with a
 * memory pcap destination (the JTAG destination needs OpenOCD and blocked the
 * first attempt) and see whether Espressif's code captures on this board. That
 * separates "our code" from "this board or this IDF version". */
