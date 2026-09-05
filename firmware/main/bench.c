#include "bench.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "usb_link.h"

static size_t s_payload_len;
static uint8_t s_pattern[SN_MAX_PAYLOAD];

static void bench_task(void *arg)
{
    (void)arg;
    int64_t next_stats_us = esp_timer_get_time() + 1000000;

    while (true) {
        if (!sn_usb_link_send(SN_FRAME_PACKET, s_pattern, s_payload_len)) {
            /* Ring full: the link cannot drain as fast as we generate, which
             * is the expected steady state. Yield so the TX task can run
             * rather than spinning and starving it. */
            vTaskDelay(1);
        }

        const int64_t now = esp_timer_get_time();
        if (now >= next_stats_us) {
            next_stats_us = now + 1000000;
            sn_link_stats_t st;
            sn_usb_link_get_stats(&st);
            sn_usb_link_send(SN_FRAME_STATS, (const uint8_t *)&st, sizeof(st));
        }

        taskYIELD();
    }
}

void sn_bench_start(size_t payload_len)
{
    if (payload_len > SN_MAX_PAYLOAD) {
        payload_len = SN_MAX_PAYLOAD;
    }
    s_payload_len = payload_len;
    for (size_t i = 0; i < payload_len; i++) {
        s_pattern[i] = (uint8_t)(i & 0xFF);
    }
    /* Priority below the TX task (10) so draining always wins over generating. */
    xTaskCreate(bench_task, "sn_bench", 4096, NULL, 5, NULL);
}
