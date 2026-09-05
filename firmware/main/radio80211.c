#include "radio80211.h"

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
#define MAX_SNAPLEN    512
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

    const uint16_t on_air = (uint16_t)pkt->rx_ctrl.sig_len;
    if (on_air == 0) {
        s_stats.skipped_zero_len++;
        return;
    }

    rx_item_t item;
    item.meta.channel = (uint8_t)pkt->rx_ctrl.channel;
    item.meta.rssi_dbm = (int8_t)pkt->rx_ctrl.rssi;
    item.meta.noise_floor = (int8_t)pkt->rx_ctrl.noise_floor;
    item.meta.timestamp_us = (uint32_t)pkt->rx_ctrl.timestamp;
    item.meta.orig_len = on_air;
    item.meta.reserved = 0;
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

    if (!s_wifi_inited) {
        esp_err_t err = nvs_flash_init();
        if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
            err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
            ESP_ERROR_CHECK(nvs_flash_erase());
            err = nvs_flash_init();
        }
        if (err != ESP_OK) {
            return err;
        }

        /* The driver posts events during start-up and needs somewhere to
         * post them. Without this it logs "failed to post WiFi event ...
         * ret=259" (invalid state) and never delivers frames. Already-created
         * is fine, since another component may have made one. */
        err = esp_event_loop_create_default();
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            return err;
        }
        /* The example reaches this via initialize_eth(); we have no Ethernet,
         * so call it directly. */
        err = esp_netif_init();
        if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
            return err;
        }

        /* WIFI_INIT_CONFIG_DEFAULT rather than a hand-rolled initialiser:
         * v6 added two fields to wifi_init_config_t, and anything filling the
         * struct by hand breaks silently. */
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        err = esp_wifi_init(&cfg);
        if (err != ESP_OK) {
            return err;
        }
        ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
        /* NULL mode: we never associate, only listen. */
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
        /* start() powers up the PHY. ESP-IDF's simple_sniffer example omits
         * it, which misled me into removing it; without it the driver accepts
         * a channel, reports ic_enable_sniffer, and never invokes the
         * callback once. Measured: callback count stayed at exactly 0. */
        ESP_ERROR_CHECK(esp_wifi_start());
        s_wifi_inited = true;
    }

    /* An explicit union rather than all-ones. ALL is documented as
     * 0xFFFFFFFF, but naming the types we want removes any doubt about
     * reserved bits being interpreted. */
    if (filter_mask == SN_80211_FILTER_ALL) {
        filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                      WIFI_PROMIS_FILTER_MASK_DATA |
                      WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    wifi_promiscuous_filter_t filter = {.filter_mask = filter_mask};
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
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
    ESP_LOGI(TAG, "capture stopped");
}

uint8_t sn_radio80211_channel(void)
{
    return s_channel;
}

void sn_radio80211_get_stats(sn_80211_stats_t *out)
{
    *out = s_stats;
}
