#include "usb_link.h"

#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

static const char *TAG = "usb_link";

#define RING_BYTES        (32 * 1024)
#define TX_CHUNK          1024
#define WRITE_TIMEOUT_MS  20
#define STALL_LIMIT       50   /* consecutive zero-byte writes before giving up */

static RingbufHandle_t s_ring;
static SemaphoreHandle_t s_send_lock;
static sn_link_stats_t s_stats;
static portMUX_TYPE s_stats_lock = portMUX_INITIALIZER_UNLOCKED;
static uint16_t s_seq;

/* Single scratch buffer, guarded by s_send_lock. 4 KB is too large to put on
 * a task stack and this avoids a heap allocation on every frame. */
static uint8_t s_scratch[SN_HEADER_LEN + SN_MAX_PAYLOAD];

static inline void stats_bump(uint32_t *field, uint32_t by)
{
    portENTER_CRITICAL(&s_stats_lock);
    *field += by;
    portEXIT_CRITICAL(&s_stats_lock);
}

static void tx_task(void *arg)
{
    (void)arg;
    uint32_t consecutive_stalls = 0;

    while (true) {
        size_t got = 0;
        uint8_t *chunk = (uint8_t *)xRingbufferReceiveUpTo(
            s_ring, &got, pdMS_TO_TICKS(100), TX_CHUNK);
        if (chunk == NULL) {
            continue;
        }

        size_t written = 0;
        while (written < got) {
            const int w = usb_serial_jtag_write_bytes(
                chunk + written, got - written, pdMS_TO_TICKS(WRITE_TIMEOUT_MS));
            if (w > 0) {
                if ((size_t)w < got - written) {
                    stats_bump(&s_stats.short_writes, 1);
                }
                written += (size_t)w;
                consecutive_stalls = 0;
            } else {
                consecutive_stalls++;
                stats_bump(&s_stats.tx_stalls, 1);
                if (consecutive_stalls >= STALL_LIMIT) {
                    /* ESP-IDF issue #18490: the TX state machine can wedge
                     * after a partial or failed write, and this is reported on
                     * exactly this chip revision. USB is the only link, so
                     * there is no fallback and nothing can rescue it here.
                     * Abandon the rest of this chunk and let the host resync
                     * rather than blocking the pipeline forever. */
                    ESP_LOGW(TAG, "tx wedged, discarding %u bytes",
                             (unsigned)(got - written));
                    consecutive_stalls = 0;
                    break;
                }
            }
        }

        stats_bump(&s_stats.bytes_sent, (uint32_t)written);
        vRingbufferReturnItem(s_ring, chunk);
    }
}

esp_err_t sn_usb_link_init(void)
{
    /* Not const: the driver takes a non-const pointer and v6 builds
     * -Wdiscarded-qualifiers as an error. */
    usb_serial_jtag_driver_config_t cfg = {
        .tx_buffer_size = 4096,
        .rx_buffer_size = 1024,
    };
    esp_err_t err = usb_serial_jtag_driver_install(&cfg);
    if (err != ESP_OK) {
        return err;
    }

    /* Byte buffer: contents are contiguous, so one write drains a whole chunk. */
    s_ring = xRingbufferCreate(RING_BYTES, RINGBUF_TYPE_BYTEBUF);
    if (s_ring == NULL) {
        return ESP_ERR_NO_MEM;
    }

    s_send_lock = xSemaphoreCreateMutex();
    if (s_send_lock == NULL) {
        return ESP_ERR_NO_MEM;
    }

    if (xTaskCreate(tx_task, "sn_tx", 4096, NULL, 10, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool sn_usb_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len)
{
    if (len > SN_MAX_PAYLOAD) {
        return false;
    }
    /* Short timeout: a caller blocked here would be worse than a dropped
     * frame, and the log sink can reach this from arbitrary tasks. */
    if (xSemaphoreTake(s_send_lock, pdMS_TO_TICKS(10)) != pdTRUE) {
        stats_bump(&s_stats.frames_dropped_ringfull, 1);
        return false;
    }

    const uint16_t seq = s_seq++;
    const size_t n = sn_frame_encode(s_scratch, sizeof(s_scratch), type, seq,
                                     payload, len);
    bool ok = false;
    if (n > 0) {
        ok = (xRingbufferSend(s_ring, s_scratch, n, 0) == pdTRUE);
    }
    xSemaphoreGive(s_send_lock);

    stats_bump(ok ? &s_stats.frames_sent : &s_stats.frames_dropped_ringfull, 1);
    return ok;
}

void sn_usb_link_get_stats(sn_link_stats_t *out)
{
    portENTER_CRITICAL(&s_stats_lock);
    *out = s_stats;
    portEXIT_CRITICAL(&s_stats_lock);
}
