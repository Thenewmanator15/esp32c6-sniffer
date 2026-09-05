#include "bench.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "usb_link.h"

static size_t s_payload_len;
static uint8_t s_pattern[SN_MAX_PAYLOAD];

/* Quiet window before streaming starts.
 *
 * The benchmark saturates the USB link, which leaves esptool unable to talk to
 * the board: reflashing fails with "esptool exit 2" because the flood drowns
 * the sync handshake. esptool resets the chip first, so a few seconds of
 * silence after boot gives it a window to connect. Without this the board can
 * only be recovered by holding BOOT and tapping RESET by hand. */
#define BENCH_STARTUP_QUIET_MS 5000

static void bench_task(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(BENCH_STARTUP_QUIET_MS));

    int64_t next_stats_us = esp_timer_get_time() + 1000000;

    while (true) {
        /* Blocking send. Waiting for ring space rather than discarding means
         * the measured figure is the rate the link genuinely sustains, not the
         * rate at which an over-eager generator can be thrown away. Frames
         * dropped here would be an artefact of the test, not of the transport,
         * and would make the drop counters meaningless. */
        sn_usb_link_send_wait(SN_FRAME_PACKET, s_pattern, s_payload_len, 1000);

        const int64_t now = esp_timer_get_time();
        if (now >= next_stats_us) {
            next_stats_us = now + 1000000;
            sn_link_stats_t st;
            sn_usb_link_get_stats(&st);
            /* Also blocking: a dropped stats frame would consume a sequence
             * number and show up on the host as a lost frame. */
            sn_usb_link_send_wait(SN_FRAME_STATS, (const uint8_t *)&st,
                                  sizeof(st), 1000);
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
