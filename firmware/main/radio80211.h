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
    /* Hardware-latched from the radio's own counter, widened here.
     *
     * The radio reports 32 bits of microseconds, which wraps every 71 minutes.
     * A capture running across a wrap saw time jump backwards by an hour in
     * the middle. The firmware counts the wraps, because it sees every frame
     * in order and the host may not. */
    uint64_t timestamp_us;
    uint16_t orig_len;     /* on-air length, so truncation stays visible */
    /* PHY of the received frame, so the host can put a real data rate and
     * modulation into radiotap instead of assuming OFDM. Previously these two
     * bytes were reserved and every frame was labelled OFDM, which is simply
     * wrong for 11b. */
    uint8_t rate;          /* rx_ctrl.rate: 11b transmission rate, else L-SIG */
    uint8_t phy;           /* low nibble cur_bb_format, high nibble secondary */
    /* The raw PHY signalling field, forwarded rather than decoded.
     *
     * For an 11n frame this is HT-SIG, whose low seven bits are the modulation
     * and coding index; for 11ax it is HE-SIG-A. Decoding happens on the host,
     * where it can be unit-tested against the standard's bit layout instead of
     * being trusted on a board whose receiver is often deaf. */
    uint32_t siga1;        /* rx_ctrl.he_siga1: HT-SIG, or HE-SIG-A1 */
    uint16_t siga2;        /* rx_ctrl.he_siga2: HE-SIG-A2 */
} sn_80211_meta_t;

#define SN_80211_PHY_FORMAT(p) ((uint8_t)((p) & 0x0Fu))
#define SN_80211_PHY_SECOND(p) ((uint8_t)(((p) >> 4) & 0x0Fu))

/* Deliver every frame type. Numerically equal to
 * WIFI_PROMIS_FILTER_MASK_ALL, defined here so callers need not pull in
 * esp_wifi.h. Note the field is a PASS mask despite being called a filter:
 * all-ones means deliver everything, not block everything. */
#define SN_80211_FILTER_ALL 0xFFFFFFFFu

#define SN_80211_FLAG_TRUNCATED 0x01u /* payload cut to the snapshot length */
#define SN_80211_FLAG_RX_ERROR  0x02u /* radio reported a reception error */
/* Part of an aggregate rather than a single MPDU. Radiotap has a field for
 * this, and it changes how a busy channel should be read: one A-MPDU is one
 * transmission opportunity, not twenty. */
#define SN_80211_FLAG_AMPDU     0x04u

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
    /* This board's Wi-Fi receiver goes deaf for minutes at a time; see the
     * STATUS note at the foot of this header. These two make that visible
     * rather than indistinguishable from a quiet channel. */
    uint32_t stalled_seconds; /* consecutive seconds with the radio up and no callback */
    uint32_t recoveries;      /* times the driver was torn down and rebuilt */
    uint32_t csi_records;     /* CSI records forwarded */
    uint32_t csi_dropped;     /* CSI records dropped, queue full or oversized */
    /* Frames whose dump_len could not be trusted, so the FCS could not be
     * stripped. Those frames carry four extra bytes the host cannot account
     * for. */
    uint32_t fcs_length_unknown;
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
esp_err_t sn_radio80211_scan(uint16_t *out_ap_count, bool active);

/* Sets the snapshot length for subsequent frames, 1..SN_80211_MAX_SNAPLEN.
 * Takes effect immediately; frames already queued keep the old length. */
esp_err_t sn_radio80211_set_snaplen(uint16_t snaplen);

/* Sets which frame types are delivered, as a wifi_promiscuous_filter_t mask.
 * Dropping control frames is the cheapest way to survive a busy channel: they
 * are the most numerous and the least informative. */
esp_err_t sn_radio80211_set_filter(uint32_t filter_mask);

/* Call once a second while capturing.
 *
 * Watches for the receiver going deaf -- the radio reports running, every call
 * returned ESP_OK, and the callback simply never fires -- and after
 * SN_80211_STALL_LIMIT_S rebuilds the driver from scratch. Returns true if it
 * performed a recovery on this call.
 *
 * Without this a deaf stretch is silent, and indistinguishable from a channel
 * with nothing on it. */
bool sn_radio80211_service(void);

/* Seconds of a running radio with no callback before the driver is rebuilt.
 * Long enough not to fire on a genuinely idle channel: even an empty 2.4 GHz
 * channel carries beacons from neighbours roughly every 100 ms. */
#define SN_80211_STALL_LIMIT_S 15u

/* Ceiling for the backoff after repeated rebuilds fail to help. */
#define SN_80211_STALL_LIMIT_MAX_S 120u

/* 802.11 frame check sequence, always four bytes, always present in what the
 * promiscuous callback hands over. */
#define SN_80211_FCS_LEN 4

#define SN_80211_MAX_SNAPLEN 512

/* Channel bandwidth, as the secondary-channel position. Sniffing a 40 MHz
 * network on its primary channel alone sees the 20 MHz half and mislabels the
 * rest, so this has to match the network being watched. */
typedef enum {
    SN_80211_BW_20 = 0,
    SN_80211_BW_40_ABOVE = 1,
    SN_80211_BW_40_BELOW = 2,
} sn_80211_bandwidth_t;

esp_err_t sn_radio80211_set_bandwidth(uint8_t bandwidth);

/* Subtype mask for control frames, a wifi_promiscuous_filter_t ctrl mask.
 * Acknowledgements are the bulk of control-frame volume and carry almost
 * nothing, so dropping them alone is often the difference between keeping up
 * and not. */
esp_err_t sn_radio80211_set_ctrl_filter(uint32_t mask);

/* Channel state information: the per-subcarrier channel response for every
 * frame received, which is what RSSI is a single scalar summary of.
 *
 * Enabling it costs bandwidth -- a few hundred bytes per frame on top of the
 * frame itself -- and it is off by default. There is nowhere in a pcap to put
 * it, so records go to the host as their own frame type. */
esp_err_t sn_radio80211_set_csi(bool enable);

/* Largest CSI record the firmware will forward. HT40 with all long training
 * fields is the worst case. */
#define SN_80211_CSI_MAX 512

/* CSI record payload, little-endian, then csi_len bytes of signed pairs:
 *
 *     uint64 timestamp_us
 *     int8   rssi_dbm
 *     int8   noise_floor
 *     uint8  channel
 *     uint8  phy          low nibble format, high nibble secondary channel
 *     uint8  mac[6]       source
 *     uint16 rx_seq
 *     uint8  flags        bit 0: first four bytes of CSI are invalid
 *     uint16 csi_len
 */
/* 8 + 1 + 1 + 1 + 1 + 6 + 2 + 1 + 2. Written out rather than left as a bare
 * number because getting it wrong truncates the last byte of every record and
 * the host rejects the lot -- which is exactly what happened. */
#define SN_80211_CSI_HEADER 23
#define SN_80211_CSI_FLAG_FIRST_WORD_INVALID 0x01u

/* Performs a scan and emits one SN_FRAME_AP_RECORD per access point found,
 * before the command reply carrying the count. Payload layout, little-endian:
 *
 *     int8   rssi_dbm
 *     uint8  channel
 *     uint8  authmode      wifi_auth_mode_t
 *     uint8  ssid_len
 *     uint8  bssid[6]
 *     char   ssid[ssid_len]   not NUL terminated
 */
#define SN_80211_AP_RECORD_HEADER 10

#ifdef __cplusplus
}
#endif

/* STATUS: Wi-Fi capture works, and the receiver is intermittently deaf.
 *
 * Measured working, channel 6: 731 frames in 15 s, 632 management and 99 data,
 * RSSI -50 to -96 dBm, qfull=0 rej=0, decoding in Wireshark as radiotap.
 *
 * INTERMITTENCY. The receiver stops hearing anything for minutes at a time,
 * across power cycles, with no software change between states. Espressif's own
 * unmodified scan binary shows it: 9, 8, 8 access points, then zero on five
 * consecutive boots. Our firmware likewise went 665 frames one minute and 0 the
 * next. Interleaved 802.15.4 captures on the same antenna worked every time.
 * Not the band (a strong channel-6 AP was present at 82 % during a failing
 * stretch), not the RF switch (explicitly powered, and 802.15.4 shares it), and
 * not NVS calibration (a full erase-flash does not clear it). Not yet
 * characterised, so nothing has been reported upstream. Retry before believing
 * a zero.
 *
 * Two defects here WERE ours, and both are fixed:
 *
 *   1. Espressif's examples never drive GPIO3, which is pulled UP at reset and
 *      leaves the XIAO's FM8625H switch unpowered, so every stock example was
 *      deaf by construction. "Their own example fails too" was no evidence.
 *   2. sn_radio80211_scan() ran before anything initialised the driver and got
 *      ESP_ERR_WIFI_NOT_INIT from its first call. It reported zero access
 *      points, and the zero was read as "heard nothing" instead of "never
 *      switched on". See wifi_init_once() below.
 *
 * A claimed v6.0.2-vs-v6.1 PHY regression did not survive an A/B/A either:
 * v6.0.2 -> 9 APs, v6.1 -> 8, v6.0.2 -> 8. With an intermittent fault in the
 * loop, one reading measures the moment, not the system.
 *
 * Full write-up: docs/2026-09-05-wifi-investigation-postmortem.md
 *
 * Traps worth keeping. Building with SDKCONFIG_DEFAULTS overwrites the
 * project's root sdkconfig, which silently disabled 802.15.4 in what was meant
 * to be the full build. A zeroed wifi_scan_config_t means zero dwell per
 * channel, so it finds nothing however loud the air is. And
 * netsh wlan show networks returns a CACHE: it read one 5 GHz network for two
 * minutes before refreshing to eight on 2.4 GHz. */
