#include "board.h"
#include "frame.h"

#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

static uint8_t s_scratch[SN_HEADER_LEN + SN_MAX_PAYLOAD];

/* Mirrors host/tests/vectors/golden.json. Keep the two in step. */
static void emit_conformance_vectors(void)
{
    uint8_t all_bytes[256];
    for (int i = 0; i < 256; i++) {
        all_bytes[i] = (uint8_t)i;
    }
    const uint8_t newline_bytes[] = {0x0a, 0x0d, 0x0a, 0x00, 0xff};
    static const char hello[] = "hello";
    static const char wrap[] = "wrap";
    static const char logmsg[] = "I (123) tag: msg";

    const struct {
        sn_frame_type_t type;
        uint16_t seq;
        const uint8_t *payload;
        size_t len;
    } cases[] = {
        {SN_FRAME_HEARTBEAT, 0, NULL, 0},
        {SN_FRAME_PACKET, 1, (const uint8_t *)hello, sizeof(hello) - 1},
        {SN_FRAME_PACKET, 2, newline_bytes, sizeof(newline_bytes)},
        {SN_FRAME_PACKET, 3, all_bytes, sizeof(all_bytes)},
        {SN_FRAME_PACKET, 65535, (const uint8_t *)wrap, sizeof(wrap) - 1},
        {SN_FRAME_LOG, 42, (const uint8_t *)logmsg, sizeof(logmsg) - 1},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        const size_t n = sn_frame_encode(s_scratch, sizeof(s_scratch),
                                         cases[i].type, cases[i].seq,
                                         cases[i].payload, cases[i].len);
        if (n == 0) {
            ESP_LOGE(TAG, "encode failed for case %u", (unsigned)i);
            continue;
        }
        size_t written = 0;
        while (written < n) {
            const int w = usb_serial_jtag_write_bytes(s_scratch + written,
                                                      n - written,
                                                      pdMS_TO_TICKS(1000));
            if (w <= 0) {
                ESP_LOGW(TAG, "short write on case %u", (unsigned)i);
                break;
            }
            written += (size_t)w;
        }
    }
}

void app_main(void)
{
    ESP_ERROR_CHECK(sn_board_init(SN_ANTENNA_INTERNAL));

    /* Not const: usb_serial_jtag_driver_install takes a non-const pointer,
     * and ESP-IDF v6 builds -Wdiscarded-qualifiers as an error. */
    usb_serial_jtag_driver_config_t cfg = {
        .tx_buffer_size = 4096,
        .rx_buffer_size = 1024,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));

    /* Repeat the burst so a host that attaches late still catches it. */
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        emit_conformance_vectors();
        ESP_LOGI(TAG, "conformance vectors emitted");
    }
}
