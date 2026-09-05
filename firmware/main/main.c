#include "board.h"
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
 *
 * They cannot share a build: the benchmark saturates the link, which would
 * swamp the conformance burst. Override from the command line with
 *   idf.py build -DSN_MODE=1
 * or edit the default here.
 */
#ifndef SN_MODE
#define SN_MODE 0
#endif

#if SN_MODE == 1
#include "bench.h"
#ifndef SN_BENCH_PAYLOAD
#define SN_BENCH_PAYLOAD 256
#endif
#endif

static const char *TAG = "main";

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
    ESP_ERROR_CHECK(sn_board_init(SN_ANTENNA_INTERNAL));
    ESP_ERROR_CHECK(sn_usb_link_init());
    sn_log_sink_install();

    ESP_LOGI(TAG, "link up, mode=%d", SN_MODE);

#if SN_MODE == 1
    sn_bench_start(SN_BENCH_PAYLOAD);
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
#else
    while (true) {
        vTaskDelay(pdMS_TO_TICKS(2000));
        emit_conformance_vectors();
    }
#endif
}
