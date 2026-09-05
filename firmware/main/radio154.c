#include "radio154.h"

#include <string.h>

#include "esp_ieee802154.h"
#include "esp_log.h"
#include "frame.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "usb_link.h"

static const char *TAG = "radio154";

/* Deeper than the driver's own buffer count so a burst is absorbed rather than
 * refused while the USB task drains. Each entry is only a pointer plus its
 * metadata. */
#define RX_QUEUE_LEN 32

typedef struct {
    uint8_t *frame;                     /* driver-owned until we release it */
    esp_ieee802154_frame_info_t info;
} rx_item_t;

static QueueHandle_t s_rx_queue;
static TaskHandle_t s_rx_task;
static uint8_t s_channel;
static volatile bool s_running;
static sn_154_stats_t s_stats;

/* Scratch for one outgoing frame: metadata plus the largest possible PSDU.
 * Only the sender task touches it. */
static uint8_t s_out[sizeof(sn_154_meta_t) + 256];

/* Receive callback. Overrides a weak symbol in the driver and runs in the
 * receive interrupt.
 *
 * Deliberately does not copy the frame. The driver hands over a buffer that
 * stays ours until esp_ieee802154_receive_handle_done(), so the sender task
 * streams straight from it. The reference implementation for this chip copies
 * here unnecessarily. */
void esp_ieee802154_receive_done(uint8_t *frame,
                                 esp_ieee802154_frame_info_t *frame_info)
{
    rx_item_t item = {.frame = frame, .info = *frame_info};
    BaseType_t woken = pdFALSE;

    if (xQueueSendFromISR(s_rx_queue, &item, &woken) != pdTRUE) {
        /* No room. Release immediately or the driver runs out of buffers and
         * silently drops everything thereafter. */
        s_stats.isr_queue_full++;
        esp_ieee802154_receive_handle_done(frame);
    }
    if (woken == pdTRUE) {
        portYIELD_FROM_ISR();
    }
}

static void rx_task(void *arg)
{
    (void)arg;
    rx_item_t item;

    while (true) {
        if (xQueueReceive(s_rx_queue, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }

        /* frame[0] is the PHY header length byte; the PSDU follows.
         *
         * The last two bytes of the PSDU are NOT the frame check sequence.
         * The radio substitutes the signal strength and link quality in their
         * place, which was verified against live traffic: on 12 of 12 frames
         * the trailing bytes equalled info.rssi (as a signed byte) and
         * info.lqi exactly. Passing them through as an FCS made Wireshark
         * report "Bad FCS" on every single frame.
         *
         * So they are dropped. Nothing is lost, because the same two values
         * travel in the metadata below, and the host declares no FCS. */
        const uint8_t raw_len = item.frame[0];
        const uint8_t *psdu = item.frame + 1;
        const uint8_t psdu_len = (raw_len >= 2u) ? (uint8_t)(raw_len - 2u) : 0u;

        if (psdu_len > 0 && psdu_len <= 127) {
            sn_154_meta_t meta = {
                .channel = item.info.channel,
                .lqi = item.info.lqi,
                .rssi_dbm = item.info.rssi,
                .flags = 0u, /* no FCS present, see above */
                .timestamp_us = item.info.timestamp,
            };
            memcpy(s_out, &meta, sizeof(meta));
            memcpy(s_out + sizeof(meta), psdu, psdu_len);

            if (sn_usb_link_send(SN_FRAME_PACKET, s_out,
                                 sizeof(meta) + psdu_len)) {
                s_stats.frames_captured++;
            } else {
                s_stats.link_rejected++;
            }
        }

        /* Release only after the frame has been handed to the link. */
        esp_ieee802154_receive_handle_done(item.frame);
    }
}

esp_err_t sn_radio154_start(uint8_t channel)
{
    if (channel < SN_154_CHANNEL_MIN || channel > SN_154_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_running) {
        return sn_radio154_set_channel(channel);
    }

    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(RX_QUEUE_LEN, sizeof(rx_item_t));
        if (s_rx_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_rx_task == NULL) {
        /* Below the USB sender (10) so draining the link always wins. */
        if (xTaskCreate(rx_task, "sn_154", 4096, NULL, 9, &s_rx_task) != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t err = esp_ieee802154_enable();
    if (err != ESP_OK) {
        return err;
    }
    /* Also disables auto-ACK receive, auto-ACK transmit and enhanced-ACK
     * transmit. Correct for passive observation: we must never acknowledge
     * traffic we are only watching. It also means promiscuous mode and
     * participating in a network are mutually exclusive. */
    err = esp_ieee802154_set_promiscuous(true);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_ieee802154_set_rx_when_idle(true);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_ieee802154_set_channel(channel);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_ieee802154_receive();
    if (err != ESP_OK) {
        return err;
    }

    s_channel = channel;
    s_running = true;
    ESP_LOGI(TAG, "capturing on channel %u", (unsigned)channel);
    return ESP_OK;
}

esp_err_t sn_radio154_set_channel(uint8_t channel)
{
    if (channel < SN_154_CHANNEL_MIN || channel > SN_154_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_running) {
        return sn_radio154_start(channel);
    }
    esp_err_t err = esp_ieee802154_set_channel(channel);
    if (err != ESP_OK) {
        return err;
    }
    s_channel = channel;
    /* Re-arm: changing channel can leave the receiver idle. */
    err = esp_ieee802154_receive();
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "channel now %u", (unsigned)channel);
    }
    return err;
}

void sn_radio154_stop(void)
{
    if (!s_running) {
        return;
    }
    esp_ieee802154_disable();
    s_running = false;
    ESP_LOGI(TAG, "capture stopped");
}

uint8_t sn_radio154_channel(void)
{
    return s_channel;
}

void sn_radio154_get_stats(sn_154_stats_t *out)
{
    *out = s_stats;
}
