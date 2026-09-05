#include "log_sink.h"

#include <stdarg.h>
#include <stdio.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "usb_link.h"

#define LOG_BUF_LEN 256

static SemaphoreHandle_t s_lock;
static char s_buf[LOG_BUF_LEN];

static int log_to_frame(const char *fmt, va_list args)
{
    /* Never block a logging call. A caller may hold other locks, and log
     * output is not worth a deadlock, so drop the line if busy. */
    if (s_lock == NULL || xSemaphoreTake(s_lock, 0) != pdTRUE) {
        return 0;
    }

    const int n = vsnprintf(s_buf, sizeof(s_buf), fmt, args);
    if (n > 0) {
        const size_t len =
            (n < (int)sizeof(s_buf)) ? (size_t)n : sizeof(s_buf) - 1;
        sn_usb_link_send(SN_FRAME_LOG, (const uint8_t *)s_buf, len);
    }

    xSemaphoreGive(s_lock);
    return n;
}

void sn_log_sink_install(void)
{
    s_lock = xSemaphoreCreateMutex();
    /* Return value deliberately discarded: we never restore the previous
     * handler, and an unused static would fail the v6 warnings-as-errors build. */
    (void)esp_log_set_vprintf(log_to_frame);
}
