#include "board.h"
#include "control.h"
#include "frame.h"
#include "log_sink.h"
#include "usb_link.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/* Build-time mode.
 *
 *   0 = conformance: repeats the golden-vector burst, for the host test suite.
 *   1 = benchmark:   streams frames flat out, for throughput measurement.
 *   2 = capture:     802.15.4 sniffing, idle until the host selects a channel.
 *
 * They cannot share a build. The benchmark saturates the link, which would
 * swamp the conformance burst; and the burst would pollute a real capture with
 * synthetic frames, which must never reach a pcap file. Select with
 *   idf.py build -DSN_MODE=2
 */
#ifndef SN_MODE
#define SN_MODE 0
#endif

#define SN_MODE_CONFORMANCE 0
#define SN_MODE_BENCHMARK   1
#define SN_MODE_CAPTURE     2

#if SN_MODE == SN_MODE_CAPTURE
#include "radio154.h"
#endif

#if SN_MODE == 1
#include "bench.h"
#ifndef SN_BENCH_PAYLOAD
#define SN_BENCH_PAYLOAD 256
#endif
#endif

/* Reported by GET_INFO so the host can check it is talking to what it expects. */
#define SN_FIRMWARE_VERSION 1u

static const char *TAG = "main";

static sn_antenna_t s_antenna = SN_ANTENNA_INTERNAL;

static sn_status_t on_command(sn_command_t cmd, uint32_t value,
                              uint32_t *out_value)
{
    switch (cmd) {
    case SN_CMD_GET_INFO:
        *out_value = SN_FIRMWARE_VERSION;
        return SN_STATUS_OK;

    case SN_CMD_SET_ANTENNA:
        if (value > 1u) {
            return SN_STATUS_BAD_VALUE;
        }
        s_antenna = (value == 1u) ? SN_ANTENNA_EXTERNAL : SN_ANTENNA_INTERNAL;
        if (sn_board_init(s_antenna) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        *out_value = value;
        return SN_STATUS_OK;

#if SN_MODE == SN_MODE_CAPTURE
    case SN_CMD_SET_CHANNEL:
    case SN_CMD_START:
        if (value < SN_154_CHANNEL_MIN || value > SN_154_CHANNEL_MAX) {
            return SN_STATUS_BAD_VALUE;
        }
        if (sn_radio154_start((uint8_t)value) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        *out_value = sn_radio154_channel();
        return SN_STATUS_OK;

    case SN_CMD_STOP:
        sn_radio154_stop();
        return SN_STATUS_OK;
#else
    case SN_CMD_SET_CHANNEL:
    case SN_CMD_START:
    case SN_CMD_STOP:
        /* Only the capture build has a radio. Reporting failure is honest;
         * silently accepting would let the host believe a channel was set. */
        return SN_STATUS_FAILED;
#endif

    default:
        return SN_STATUS_UNKNOWN_COMMAND;
    }
}

/* Mirrors host/tests/vectors/golden.json in payload and type. Sequence numbers
 * are assigned by the link, so the host test compares payloads and types
 * rather than whole encoded frames. */
static void emit_conformance_vectors(void)
{
    uint8_t all_bytes[256];
    for (int i = 0; i < 256; i++) {
        all_bytes[i] = (uint8_t)i;
    }
    static const uint8_t newline_bytes[] = {0x0a, 0x0d, 0x0a, 0x00, 0xff};
    static const char hello[] = "hello";
    static const char wrap[] = "wrap";
    static const char logmsg[] = "I (123) tag: msg";

    sn_usb_link_send(SN_FRAME_HEARTBEAT, NULL, 0);
    sn_usb_link_send(SN_FRAME_PACKET, (const uint8_t *)hello, sizeof(hello) - 1);
    sn_usb_link_send(SN_FRAME_PACKET, newline_bytes, sizeof(newline_bytes));
    sn_usb_link_send(SN_FRAME_PACKET, all_bytes, sizeof(all_bytes));
    sn_usb_link_send(SN_FRAME_PACKET, (const uint8_t *)wrap, sizeof(wrap) - 1);
    sn_usb_link_send(SN_FRAME_LOG, (const uint8_t *)logmsg, sizeof(logmsg) - 1);
}

void app_main(void)
{
    ESP_ERROR_CHECK(sn_board_init(s_antenna));
    ESP_ERROR_CHECK(sn_usb_link_init());
    sn_log_sink_install();

    sn_control_set_handler(on_command);
    ESP_ERROR_CHECK(sn_control_start());

    ESP_LOGI(TAG, "link up, mode=%d", SN_MODE);

#if SN_MODE == SN_MODE_BENCHMARK
    sn_bench_start(SN_BENCH_PAYLOAD);
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

#elif SN_MODE == SN_MODE_CAPTURE
    /* Idle until the host selects a channel. Starting a radio unasked would
     * put frames on the wire before anyone is reading, and the link discards
     * data when nothing drains it. */
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        sn_154_stats_t rs;
        sn_radio154_get_stats(&rs);
        if (rs.isr_queue_full || rs.link_rejected) {
            /* A drop here is a defect, not physics: a saturated 802.15.4
             * channel is ~31 kB/s against a measured ~810 kB/s link. */
            ESP_LOGW(TAG, "dropped frames: isr=%u link=%u",
                     (unsigned)rs.isr_queue_full, (unsigned)rs.link_rejected);
        }
    }

#else
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        emit_conformance_vectors();
    }
#endif
}
