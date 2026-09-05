#include "radio80211.h"

#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "frame.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "usb_link.h"

static const char *TAG = "radio80211";

/* Espressif's own guidance for this callback is blunt: it runs in the Wi-Fi
 * driver task, and if the application does much work per frame it should post
 * elsewhere and defer. They also warn that promiscuous mode "has a great impact
 * on throughput". So the callback copies and queues, nothing more. */
#define RX_QUEUE_LEN   24
#define MAX_SNAPLEN    SN_80211_MAX_SNAPLEN
#define DEFAULT_SNAPLEN 256

typedef struct {
    sn_80211_meta_t meta;
    uint16_t len;
    uint8_t data[MAX_SNAPLEN];
} rx_item_t;

static QueueHandle_t s_rx_queue;
static TaskHandle_t s_rx_task;
static uint8_t s_channel;
static uint16_t s_snaplen = DEFAULT_SNAPLEN;
static volatile bool s_running;
static sn_80211_stats_t s_stats;
static bool s_wifi_inited;
static uint32_t s_filter_mask = SN_80211_FILTER_ALL;
/* Snapshot of the callback count at the last service() tick, to spot a
 * receiver that has stopped delivering without reporting anything. */
static uint32_t s_last_seen_callbacks;
/* Grows each time a rebuild fails to bring the receiver back, so a fault the
 * driver cannot fix is not met by tearing the stack down every 15 seconds
 * forever. Reset as soon as a frame arrives. */
static uint32_t s_stall_limit = SN_80211_STALL_LIMIT_S;
/* Wrap tracking for the radio's 32-bit microsecond counter. Touched only by
 * the receive callback, which is serialised by the driver task. */
static uint32_t s_ts_last;
static uint64_t s_ts_epoch;

/* Sender-owned; only the rx task touches it. */
static uint8_t s_out[sizeof(sn_80211_meta_t) + MAX_SNAPLEN];

static void promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    s_stats.callbacks++;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    if (pkt == NULL) {
        return;
    }

    /* MISC frames carry no usable payload. */
    if (type == WIFI_PKT_MISC) {
        s_stats.skipped_misc++;
        return;
    }

    /* sig_len counts the MPDU INCLUDING its frame check sequence; dump_len is
     * the same frame without it. Sending sig_len bytes while telling the host
     * there is no FCS -- which is what this did -- leaves four bytes of CRC on
     * the end of every frame for Wireshark to parse as information elements.
     * Truncation hid it on long frames and it showed up on short ones.
     *
     * So the FCS is dropped and no FCS is declared, which is true. Nothing is
     * lost: rx_state already reports whether the radio liked the frame, and it
     * saves four bytes per frame on a link that is the binding constraint. */
    uint16_t on_air = (uint16_t)pkt->rx_ctrl.sig_len;
    const uint16_t without_fcs = (uint16_t)pkt->rx_ctrl.dump_len;
    if (without_fcs > 0u && without_fcs <= on_air) {
        on_air = without_fcs;
    }
    if (on_air == 0) {
        s_stats.skipped_zero_len++;
        return;
    }

    rx_item_t item;
    item.meta.channel = (uint8_t)pkt->rx_ctrl.channel;
    item.meta.rssi_dbm = (int8_t)pkt->rx_ctrl.rssi;
    item.meta.noise_floor = (int8_t)pkt->rx_ctrl.noise_floor;
    /* Widen the 32-bit counter. A backwards step of more than half the range
     * is a wrap; a smaller one is the counter being reset, which happens when
     * the driver is torn down and rebuilt after a stall, and must NOT be
     * counted as 71 minutes of elapsed time. */
    const uint32_t raw_ts = (uint32_t)pkt->rx_ctrl.timestamp;
    if (raw_ts < s_ts_last && (s_ts_last - raw_ts) > 0x80000000u) {
        s_ts_epoch += 0x100000000ull;
    }
    s_ts_last = raw_ts;
    item.meta.timestamp_us = s_ts_epoch + raw_ts;
    item.meta.orig_len = on_air;
    /* cur_bb_format distinguishes 11b from everything else, so the host can
     * label CCK as CCK. Assuming OFDM for every frame was wrong for 11b, which
     * is exactly what beacons from older access points use. */
    item.meta.rate = (uint8_t)pkt->rx_ctrl.rate;
    item.meta.phy = (uint8_t)((pkt->rx_ctrl.cur_bb_format & 0x0Fu) |
                              ((pkt->rx_ctrl.second & 0x0Fu) << 4));
    /* Forwarded raw; the host decodes it. */
    item.meta.siga1 = (uint32_t)pkt->rx_ctrl.he_siga1;
    item.meta.siga2 = (uint16_t)pkt->rx_ctrl.he_siga2;
    item.meta.flags = (pkt->rx_ctrl.rx_state != 0) ? SN_80211_FLAG_RX_ERROR : 0u;

    uint16_t take = on_air;
    if (take > s_snaplen) {
        take = s_snaplen;
        item.meta.flags |= SN_80211_FLAG_TRUNCATED;
    }
    if (take > MAX_SNAPLEN) {
        take = MAX_SNAPLEN;
    }
    item.len = take;

    /* Copy now. Unlike the 802.15.4 driver, which hands over a buffer we own
     * until we release it, this buffer's lifetime is undocumented and the
     * driver is closed source. Retaining the pointer would be a guess. */
    memcpy(item.data, pkt->payload, take);

    if (xQueueSend(s_rx_queue, &item, 0) != pdTRUE) {
        s_stats.isr_queue_full++;
        return;
    }
    if (take < on_air) {
        s_stats.frames_truncated++;
        s_stats.bytes_dropped_by_snaplen += (uint32_t)(on_air - take);
    }
}

static void rx_task(void *arg)
{
    (void)arg;
    static rx_item_t item;

    while (true) {
        if (xQueueReceive(s_rx_queue, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        memcpy(s_out, &item.meta, sizeof(item.meta));
        memcpy(s_out + sizeof(item.meta), item.data, item.len);

        if (sn_usb_link_send(SN_FRAME_PACKET, s_out,
                             sizeof(item.meta) + item.len)) {
            s_stats.frames_captured++;
        } else {
            s_stats.link_rejected++;
        }
    }
}

/* Brings the Wi-Fi driver up, once. Mode and start are deliberately NOT done
 * here: promiscuous capture wants NULL mode and scanning wants STA, so each
 * caller sets its own and then starts.
 *
 * This lived inside sn_radio80211_start() and nothing else could reach it,
 * so sn_radio80211_scan() -- which never calls start() -- ran against an
 * uninitialised driver and returned ESP_ERR_WIFI_NOT_INIT from its very first
 * call. The scan reported zero access points, and zero was read as "the radio
 * heard nothing" rather than "the radio was never switched on". That mistake
 * cost a long detour into imagined hardware faults. */
static esp_err_t wifi_init_once(void)
{
    if (s_wifi_inited) {
        return ESP_OK;
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        return err;
    }

    /* The driver posts events during start-up and needs somewhere to post
     * them. Without this it logs "failed to post WiFi event ... ret=259"
     * (invalid state) and never delivers frames. Already-created is fine,
     * since another component may have made one. */
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }
    /* The example reaches this via initialize_eth(); we have no Ethernet, so
     * call it directly. */
    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    /* WIFI_INIT_CONFIG_DEFAULT rather than a hand-rolled initialiser: v6 added
     * two fields to wifi_init_config_t, and anything filling the struct by hand
     * breaks silently. */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        return err;
    }
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    s_wifi_inited = true;
    return ESP_OK;
}

/* An explicit union rather than all-ones. ALL is documented as 0xFFFFFFFF, but
 * naming the types we want removes any doubt about reserved bits being
 * interpreted. */
static esp_err_t apply_filter(uint32_t filter_mask)
{
    if (filter_mask == SN_80211_FILTER_ALL) {
        filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                      WIFI_PROMIS_FILTER_MASK_DATA |
                      WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    wifi_promiscuous_filter_t filter = {.filter_mask = filter_mask};
    return esp_wifi_set_promiscuous_filter(&filter);
}

esp_err_t sn_radio80211_set_snaplen(uint16_t snaplen)
{
    if (snaplen == 0u || snaplen > MAX_SNAPLEN) {
        return ESP_ERR_INVALID_ARG;
    }
    s_snaplen = snaplen;
    ESP_LOGI(TAG, "snaplen now %u", (unsigned)snaplen);
    return ESP_OK;
}

esp_err_t sn_radio80211_set_filter(uint32_t filter_mask)
{
    s_filter_mask = filter_mask;
    if (!s_running) {
        return ESP_OK; /* remembered, applied when capture starts */
    }
    esp_err_t err = apply_filter(filter_mask);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "filter now 0x%08x", (unsigned)filter_mask);
    }
    return err;
}

esp_err_t sn_radio80211_start(uint8_t channel, uint16_t snaplen,
                              uint32_t filter_mask)
{
    if (channel < SN_80211_CHANNEL_MIN || channel > SN_80211_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (snaplen == 0 || snaplen > MAX_SNAPLEN) {
        snaplen = DEFAULT_SNAPLEN;
    }
    s_snaplen = snaplen;

    if (s_running) {
        return sn_radio80211_set_channel(channel);
    }

    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(RX_QUEUE_LEN, sizeof(rx_item_t));
        if (s_rx_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_rx_task == NULL) {
        /* Below the USB sender so draining the link always wins. */
        if (xTaskCreate(rx_task, "sn_80211", 4096, NULL, 9, &s_rx_task)
                != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t init_err = wifi_init_once();
    if (init_err != ESP_OK) {
        return init_err;
    }
    /* NULL mode: we never associate, only listen. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    /* start() powers up the PHY. ESP-IDF's simple_sniffer example omits it,
     * which misled me into removing it; without it the driver accepts a
     * channel, reports ic_enable_sniffer, and never invokes the callback
     * once. Measured: callback count stayed at exactly 0. */
    ESP_ERROR_CHECK(esp_wifi_start());

    s_filter_mask = filter_mask;
    ESP_ERROR_CHECK(apply_filter(filter_mask));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE));

    s_channel = channel;
    s_running = true;
    ESP_LOGI(TAG, "capturing on channel %u, snaplen %u",
             (unsigned)channel, (unsigned)s_snaplen);
    return ESP_OK;
}

esp_err_t sn_radio80211_set_channel(uint8_t channel)
{
    if (channel < SN_80211_CHANNEL_MIN || channel > SN_80211_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_running) {
        return sn_radio80211_start(channel, s_snaplen, SN_80211_FILTER_ALL);
    }
    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err == ESP_OK) {
        s_channel = channel;
        ESP_LOGI(TAG, "channel now %u", (unsigned)channel);
    }
    return err;
}

void sn_radio80211_stop(void)
{
    if (!s_running) {
        return;
    }
    esp_wifi_set_promiscuous(false);
    s_running = false;
    s_stats.stalled_seconds = 0;
    ESP_LOGI(TAG, "capture stopped");
}

bool sn_radio80211_service(void)
{
    if (!s_running) {
        s_stats.stalled_seconds = 0;
        s_last_seen_callbacks = s_stats.callbacks;
        return false;
    }

    if (s_stats.callbacks != s_last_seen_callbacks) {
        s_last_seen_callbacks = s_stats.callbacks;
        s_stats.stalled_seconds = 0;
        s_stall_limit = SN_80211_STALL_LIMIT_S; /* it is alive; start over */
        return false;
    }

    /* Nothing delivered since the last tick. On 2.4 GHz that is already odd:
     * neighbouring access points beacon roughly every 100 ms, so even an
     * unused channel is not silent for long. */
    s_stats.stalled_seconds++;
    if (s_stats.stalled_seconds < s_stall_limit) {
        return false;
    }

    /* Rebuild the driver completely rather than just re-arming promiscuous
     * mode.
     *
     * Measured: this does NOT clear the deafness on this board. Three
     * consecutive rebuilds left callbacks at exactly 0, so the fault is below
     * the driver, and a full erase-flash does not clear it either. The rebuild
     * is kept because it does fix an ordinary driver-level stall, and because
     * the attempt is what makes the condition visible -- but it backs off
     * rather than tearing the stack down every 15 seconds indefinitely.
     *
     * This is a workaround for a fault that is not ours: Espressif's own
     * unmodified scan binary goes deaf on this board too. It is reported in
     * the counters rather than hidden. If recoveries climb while frames do
     * not, the radio is the problem, not the code. */
    const uint8_t channel = s_channel;
    const uint16_t snaplen = s_snaplen;
    const uint32_t filter = s_filter_mask;

    ESP_LOGW(TAG, "no frames for %us on channel %u; rebuilding the driver",
             (unsigned)s_stats.stalled_seconds, (unsigned)channel);

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    s_wifi_inited = false;
    s_running = false;
    s_stats.stalled_seconds = 0;
    s_stats.recoveries++;
    /* The rebuild restarts the radio's counter. Carry the elapsed time forward
     * so timestamps keep increasing across a recovery instead of jumping back
     * to zero mid-capture. */
    s_ts_epoch += s_ts_last;
    s_ts_last = 0;

    esp_err_t err = sn_radio80211_start(channel, snaplen, filter);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rebuild failed: %s", esp_err_to_name(err));
    }
    s_last_seen_callbacks = s_stats.callbacks;

    /* Back off, capped, so a persistent fault costs one rebuild a minute
     * rather than four. Any frame at all resets this. */
    if (s_stall_limit < SN_80211_STALL_LIMIT_MAX_S) {
        s_stall_limit *= 2u;
        if (s_stall_limit > SN_80211_STALL_LIMIT_MAX_S) {
            s_stall_limit = SN_80211_STALL_LIMIT_MAX_S;
        }
    }
    return true;
}

uint8_t sn_radio80211_channel(void)
{
    return s_channel;
}

void sn_radio80211_get_stats(sn_80211_stats_t *out)
{
    *out = s_stats;
}

esp_err_t sn_radio80211_scan(uint16_t *out_ap_count, bool active)
{
    if (out_ap_count == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_ap_count = 0;

    /* Bring the driver up if capture has not already done it. Skipping this
     * was the defect described on wifi_init_once(). */
    esp_err_t err = wifi_init_once();
    ESP_LOGI(TAG, "scan: wifi_init_once -> %s", esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }

    /* Scanning needs station mode; promiscuous capture uses NULL mode.
     * Every step is logged with its error code: a bare failure return told us
     * nothing about which call was refusing. */
    err = esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "scan: set_promiscuous(false) -> %s", esp_err_to_name(err));

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    ESP_LOGI(TAG, "scan: set_mode(STA) -> %s", esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }

    err = esp_wifi_start();
    ESP_LOGI(TAG, "scan: wifi_start -> %s", esp_err_to_name(err));
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
        return err;
    }

    /* Explicit dwell times. A zeroed config means zero milliseconds per
     * channel, and a scan that never lingers finds nothing however loud the
     * air is -- a broken instrument that looks like a broken radio. */
    wifi_scan_config_t cfg = {0};
    cfg.show_hidden = true;
    if (active) {
        /* Transmits probe requests. Faster, and it finds access points that
         * are not beaconing at that moment -- but it makes the sniffer visible
         * on the air, which is the opposite of what this instrument is for.
         * Opt-in only, never the default. */
        cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
        cfg.scan_time.active.min = 120;
        cfg.scan_time.active.max = 400;
    } else {
        /* Listens for beacons and transmits nothing. The dwell has to exceed a
         * beacon interval, which is about 100 ms, or a passive scan misses the
         * very networks it is looking for. */
        cfg.scan_type = WIFI_SCAN_TYPE_PASSIVE;
        cfg.scan_time.passive = 150;
    }
    err = esp_wifi_scan_start(&cfg, true); /* blocking */
    ESP_LOGI(TAG, "scan: scan_start (%s) -> %s",
             active ? "active, transmitting probes" : "passive",
             esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }
    uint16_t n = 0;
    err = esp_wifi_scan_get_ap_num(&n);
    if (err != ESP_OK) {
        return err;
    }
    *out_ap_count = n;
    ESP_LOGI(TAG, "scan found %u access points", (unsigned)n);
    if (n == 0) {
        return ESP_OK;
    }

    /* Fetched in small batches rather than all at once: wifi_ap_record_t is
     * around 700 bytes here, so a busy area would otherwise need tens of
     * kilobytes of heap on a chip with a few hundred. */
    static const uint16_t BATCH = 4;
    wifi_ap_record_t *records = calloc(BATCH, sizeof(wifi_ap_record_t));
    if (records == NULL) {
        return ESP_ERR_NO_MEM;
    }

    uint16_t remaining = n;
    while (remaining > 0) {
        uint16_t want = (remaining > BATCH) ? BATCH : remaining;
        /* esp_wifi_scan_get_ap_records() drains the list, so each call returns
         * the next batch and the results are freed as they go. */
        if (esp_wifi_scan_get_ap_records(&want, records) != ESP_OK || want == 0) {
            break;
        }
        for (uint16_t i = 0; i < want; i++) {
            uint8_t out[SN_80211_AP_RECORD_HEADER + 32];
            size_t ssid_len = strnlen((const char *)records[i].ssid, 32);
            out[0] = (uint8_t)records[i].rssi;
            out[1] = records[i].primary;
            out[2] = (uint8_t)records[i].authmode;
            out[3] = (uint8_t)ssid_len;
            memcpy(out + 4, records[i].bssid, 6);
            memcpy(out + SN_80211_AP_RECORD_HEADER, records[i].ssid, ssid_len);
            /* Blocking: a scan result is small, rare, and worth waiting for.
             * Dropping it would leave the host with a count it cannot explain. */
            sn_usb_link_send_wait(SN_FRAME_AP_RECORD, out,
                                  SN_80211_AP_RECORD_HEADER + ssid_len, 1000);
        }
        remaining -= want;
    }
    free(records);
    return ESP_OK;
}
