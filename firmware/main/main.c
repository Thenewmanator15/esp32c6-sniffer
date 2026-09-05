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
#include "radio80211.h"

/* One radio at a time, always. The C6 has a single 2.4 GHz front end shared by
 * all three radios, and Espressif's coexistence matrix lists the pairs we would
 * want as unsupported or unstable. Selecting a radio stops the other. */
typedef enum { SN_RADIO_154 = 0, SN_RADIO_WIFI = 1 } sn_radio_t;
static sn_radio_t s_radio = SN_RADIO_154;

/* A busy 802.11 channel produces roughly 25x what the USB link carries, so
 * truncation is mandatory rather than a tuning choice. What is discarded is
 * encrypted payload; the headers worth having are at the front. */
#define SN_WIFI_SNAPLEN 256
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
    case SN_CMD_SET_RADIO:
        if (value > 1u) {
            return SN_STATUS_BAD_VALUE;
        }
        /* Stop whichever is running before switching; they share the radio. */
        sn_radio154_stop();
        sn_radio80211_stop();
        s_radio = (value == 1u) ? SN_RADIO_WIFI : SN_RADIO_154;
        *out_value = value;
        return SN_STATUS_OK;

    case SN_CMD_SET_CHANNEL:
    case SN_CMD_START:
        if (s_radio == SN_RADIO_WIFI) {
            if (value < SN_80211_CHANNEL_MIN || value > SN_80211_CHANNEL_MAX) {
                return SN_STATUS_BAD_VALUE;
            }
            sn_radio154_stop(); /* shared front end */
            if (sn_radio80211_start((uint8_t)value, SN_WIFI_SNAPLEN,
                                    SN_80211_FILTER_ALL) != ESP_OK) {
                return SN_STATUS_FAILED;
            }
            *out_value = sn_radio80211_channel();
            return SN_STATUS_OK;
        }
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
        sn_radio80211_stop();
        return SN_STATUS_OK;

    case SN_CMD_WIFI_SCAN: {
        uint16_t aps = 0;
        /* One 2.4 GHz front end, shared. A scan issued without a preceding
         * SET_RADIO would otherwise run while 802.15.4 still owns the radio. */
        sn_radio154_stop();
        if (sn_radio80211_scan(&aps) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        *out_value = aps;
        return SN_STATUS_OK;
    }

    case SN_CMD_ENERGY_DETECT: {
        /* value packs the channel in the low byte and the measurement window,
         * in 16 us symbols, in the upper three. */
        const uint8_t ed_channel = (uint8_t)(value & 0xFFu);
        const uint32_t ed_symbols = value >> 8;
        if (ed_channel < SN_154_CHANNEL_MIN ||
            ed_channel > SN_154_CHANNEL_MAX || ed_symbols == 0u) {
            return SN_STATUS_BAD_VALUE;
        }
        int8_t dbm = 0;
        if (sn_radio154_energy_detect(ed_channel, ed_symbols, &dbm) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        /* Signed, so widen through uint8_t and let the host reinterpret. */
        *out_value = (uint32_t)(uint8_t)dbm;
        return SN_STATUS_OK;
    }
#else
    case SN_CMD_SET_CHANNEL:
    case SN_CMD_START:
    case SN_CMD_STOP:
    case SN_CMD_ENERGY_DETECT:
    case SN_CMD_SET_RADIO:
    case SN_CMD_WIFI_SCAN:
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

        /* Publish both counter sets once a second so the host can prove a
         * capture was lossless rather than assume it. Nothing below us
         * reports drops: the 802.15.4 driver's buffer-full warning is
         * compiled out of default builds, and there is no Wi-Fi equivalent
         * at all. A drop on this radio is a defect, not physics, since a
         * saturated channel is ~31 kB/s against a measured ~810 kB/s link. */
        /* Not packed: both members are all uint32_t, so the layout is already
         * gap-free at 4-byte alignment. Packing would only make taking their
         * addresses unsafe, which v6 rejects as an error. */
        struct {
            sn_link_stats_t link;
            sn_154_stats_t radio;
        } combined;
        sn_usb_link_get_stats(&combined.link);
        sn_radio154_get_stats(&combined.radio);
        sn_usb_link_send(SN_FRAME_STATS, (const uint8_t *)&combined,
                         sizeof(combined));

        if (s_radio == SN_RADIO_WIFI) {
            sn_80211_stats_t w;
            sn_radio80211_get_stats(&w);
            ESP_LOGI(TAG, "wifi: cb=%u misc=%u zerolen=%u sent=%u trunc=%u "
                          "qfull=%u rej=%u",
                     (unsigned)w.callbacks, (unsigned)w.skipped_misc,
                     (unsigned)w.skipped_zero_len, (unsigned)w.frames_captured,
                     (unsigned)w.frames_truncated, (unsigned)w.isr_queue_full,
                     (unsigned)w.link_rejected);
        }

        if (combined.radio.isr_queue_full || combined.radio.link_rejected) {
            ESP_LOGW(TAG, "dropped frames: isr=%u link=%u",
                     (unsigned)combined.radio.isr_queue_full,
                     (unsigned)combined.radio.link_rejected);
        }
    }

#else
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        emit_conformance_vectors();
    }
#endif
}
