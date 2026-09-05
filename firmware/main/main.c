#include "board.h"
#include "control.h"
#include "frame.h"
#include "log_sink.h"
#include "usb_link.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_sleep.h"
#include "nvs_flash.h"

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
/* Bumped whenever the wire format changes, so the host can refuse to
 * misinterpret an older board rather than decoding rubbish confidently.
 *   1: original
 *   2: Wi-Fi counters added to the stats frame
 *   3: Wi-Fi metadata gained a 64-bit timestamp, rate/PHY and the raw signal
 *      field; AP_RECORD frames added
 *   4: A-MPDU flag, CSI frames, bandwidth and control-subtype commands
 */
#define SN_FIRMWARE_VERSION 4u

static const char *TAG = "main";

static sn_antenna_t s_antenna = SN_ANTENNA_INTERNAL;

/* Set by SN_CMD_RADIO_POWER_CYCLE and acted on by the main loop, so the reply
 * reaches the host before the chip goes down. */
static volatile bool s_power_cycle_requested;

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

    case SN_CMD_SET_SNAPLEN:
        if (sn_radio80211_set_snaplen((uint16_t)value) != ESP_OK) {
            return SN_STATUS_BAD_VALUE;
        }
        *out_value = value;
        return SN_STATUS_OK;

    case SN_CMD_SET_FILTER:
        if (sn_radio80211_set_filter(value) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        *out_value = value;
        return SN_STATUS_OK;

    case SN_CMD_SET_BANDWIDTH:
        if (sn_radio80211_set_bandwidth((uint8_t)value) != ESP_OK) {
            return SN_STATUS_BAD_VALUE;
        }
        *out_value = value;
        return SN_STATUS_OK;

    case SN_CMD_SET_CTRL_FILTER:
        if (sn_radio80211_set_ctrl_filter(value) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        *out_value = value;
        return SN_STATUS_OK;

    case SN_CMD_SET_CSI:
        if (value > 1u) {
            return SN_STATUS_BAD_VALUE;
        }
        if (sn_radio80211_set_csi(value == 1u) != ESP_OK) {
            return SN_STATUS_FAILED;
        }
        *out_value = value;
        return SN_STATUS_OK;

    case SN_CMD_RADIO_POWER_CYCLE:
        /* The strongest reset available without touching the hardware.
         *
         * Every reset used while chasing this board's deaf Wi-Fi receiver has
         * been a soft one: esptool's reset line, or a reflash. Neither removes
         * power from the radio, and neither has ever cleared the fault. Deep
         * sleep does power-gate the modem and RF domains and returns through a
         * full chip reset, so it is a real test of whether the fault is a latch
         * in a domain that can be power-cycled.
         *
         * It is NOT equivalent to unplugging: the chip's supply rail stays
         * energised and the board's RF switch keeps its own. If deep sleep
         * does not clear it but a physical unplug does, the fault lives outside
         * the gated domains.
         *
         * Deliberately a command rather than part of the automatic stall
         * recovery, because it drops the USB link and would end a running
         * capture without warning. */
        s_power_cycle_requested = true;
        *out_value = 1;
        return SN_STATUS_OK;

    case SN_CMD_WIFI_SCAN: {
        uint16_t aps = 0;
        /* One 2.4 GHz front end, shared. A scan issued without a preceding
         * SET_RADIO would otherwise run while 802.15.4 still owns the radio. */
        sn_radio154_stop();
        /* value 0 = passive, 1 = active. Passive is the default because an
         * active scan transmits probe requests, and this instrument is
         * supposed to be silent unless explicitly told otherwise. */
        if (sn_radio80211_scan(&aps, value == 1u) != ESP_OK) {
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
    case SN_CMD_SET_SNAPLEN:
    case SN_CMD_SET_FILTER:
    case SN_CMD_RADIO_POWER_CYCLE:
    case SN_CMD_SET_BANDWIDTH:
    case SN_CMD_SET_CTRL_FILTER:
    case SN_CMD_SET_CSI:
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
    /* Before any radio, and not optional.
     *
     * The PHY keeps its RF calibration in NVS and both radios share it. This
     * call used to live inside the Wi-Fi bring-up only, so starting 802.15.4
     * first brought the PHY up against an uninitialised store: it logged
     * "esp_phy_load_cal_data_from_nvs: NVS has not been initialized", fell
     * back to a full calibration, then SAVED it. Wi-Fi was deaf from that
     * point on -- callbacks stayed at exactly 0 -- and because the damage sat
     * in flash it survived power cycles and looked precisely like broken
     * hardware. It cost a long detour before the log line was actually read.
     *
     * A corrupt or version-mismatched store is erased rather than tolerated;
     * there is nothing in it worth keeping across a reflash. */
    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES ||
        nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_err);

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

        if (s_power_cycle_requested) {
            ESP_LOGW(TAG, "power-cycling the radio domain via deep sleep");
            /* Let the reply and log drain: the link is a ring the sender task
             * empties, and deep sleep discards whatever is still queued. */
            vTaskDelay(pdMS_TO_TICKS(300));
            sn_radio154_stop();
            sn_radio80211_stop();
            esp_sleep_enable_timer_wakeup(1000000ull); /* one second */
            esp_deep_sleep_start();                    /* does not return */
        }

        /* Publish both counter sets once a second so the host can prove a
         * capture was lossless rather than assume it. Nothing below us
         * reports drops: the 802.15.4 driver's buffer-full warning is
         * compiled out of default builds, and there is no Wi-Fi equivalent
         * at all. A drop on this radio is a defect, not physics, since a
         * saturated channel is ~31 kB/s against a measured ~810 kB/s link. */
        /* Not packed: both members are all uint32_t, so the layout is already
         * gap-free at 4-byte alignment. Packing would only make taking their
         * addresses unsafe, which v6 rejects as an error. */
        /* Both radios' counters go in every frame, whichever is running. The
         * host picks the block matching the radio it selected. Sending only
         * the active one would leave the host unable to tell a zero counter
         * from an absent one, and the Wi-Fi counters were previously not sent
         * at all -- they went out as a once-a-second log line, so a host
         * checking losslessness on Wi-Fi silently read the 802.15.4 block and
         * always saw zero. */
        struct {
            sn_link_stats_t link;
            sn_154_stats_t radio;
            sn_80211_stats_t wifi;
        } combined;
        /* Before reading the counters, so a rebuild is reflected in the same
         * frame that reports the stall which caused it. */
        if (s_radio == SN_RADIO_WIFI && sn_radio80211_service()) {
            ESP_LOGW(TAG, "Wi-Fi receiver went deaf; driver rebuilt");
        }

        sn_usb_link_get_stats(&combined.link);
        sn_radio154_get_stats(&combined.radio);
        sn_radio80211_get_stats(&combined.wifi);
        sn_usb_link_send(SN_FRAME_STATS, (const uint8_t *)&combined,
                         sizeof(combined));

        const uint32_t isr_full = (s_radio == SN_RADIO_WIFI)
                                      ? combined.wifi.isr_queue_full
                                      : combined.radio.isr_queue_full;
        const uint32_t rejected = (s_radio == SN_RADIO_WIFI)
                                      ? combined.wifi.link_rejected
                                      : combined.radio.link_rejected;
        if (isr_full || rejected) {
            ESP_LOGW(TAG, "dropped frames: isr=%u link=%u",
                     (unsigned)isr_full, (unsigned)rejected);
        }
    }

#else
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        emit_conformance_vectors();
    }
#endif
}
