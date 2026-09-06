/* A ring of timestamped events, for finding out where the time goes.
 *
 * The host can measure that stopping a capture takes seconds, and can measure
 * nothing about WHY: everything interesting happens inside driver calls on the
 * board. This records when each one started and finished, in microseconds, so
 * the answer comes from the firmware rather than from a guess made on the far
 * side of a USB link.
 *
 * Deliberately not ESP_LOG. A log line is formatted, copied, framed and sent
 * over USB, which costs tens of microseconds and perturbs exactly the timing
 * it is meant to report -- and cannot be used from an interrupt at all. An
 * entry here is a timestamp read and four stores.
 *
 * The ring is 8 bytes per entry and never blocks. A writer that races with the
 * dump loses or duplicates an entry rather than waiting; this is diagnostic
 * data, and a lock would change the timing under measurement.
 */

#ifndef SN_TRACE_H
#define SN_TRACE_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Power of two, so the index wraps with a mask rather than a division. */
#define SN_TRACE_SLOTS 512u

/* How many entries a dump copies out at once, and how many go in one
 * frame. 64 entries is 512 bytes, comfortably inside the link's frame
 * budget, and 512 separate frames would cost more link time than the
 * events being measured. */
#define SN_TRACE_BATCH SN_TRACE_SLOTS
#define SN_TRACE_PER_FRAME 64u

typedef enum {
    SN_TRACE_NONE = 0,

    /* Control path. arg8 is the command id; on OUT, arg16 is the status. */
    SN_TRACE_CMD_IN = 1,
    SN_TRACE_CMD_OUT = 2,

    /* Radio lifecycle. Entry and exit are separate events so the duration of
     * a driver call is visible, which is the whole point: a single event
     * cannot distinguish a slow call from a late one. */
    SN_TRACE_154_START_IN = 10,
    SN_TRACE_154_START_OUT = 11,
    SN_TRACE_154_STOP_IN = 12,
    SN_TRACE_154_STOP_OUT = 13,
    SN_TRACE_WIFI_START_IN = 20,
    SN_TRACE_WIFI_START_OUT = 21,
    SN_TRACE_WIFI_STOP_IN = 22,
    SN_TRACE_WIFI_STOP_OUT = 23,
    SN_TRACE_WIFI_INIT_IN = 24,
    SN_TRACE_WIFI_INIT_OUT = 25,
    SN_TRACE_BLE_START_IN = 30,
    SN_TRACE_BLE_START_OUT = 31,
    SN_TRACE_BLE_STOP_IN = 32,
    SN_TRACE_BLE_STOP_OUT = 33,

    /* Data path. arg16 is a length or a count. */
    SN_TRACE_RX = 40,
    SN_TRACE_RING_FULL = 41,
    SN_TRACE_TX_STALL = 42,

    SN_TRACE_MARK = 60,          /* host-injected, to line the trace up */
} sn_trace_event_t;

typedef struct {
    uint32_t us;                 /* esp_timer_get_time(), low 32 bits */
    uint8_t event;
    uint8_t arg8;
    uint16_t arg16;
} sn_trace_entry_t;

/* Records one event. Safe from an interrupt, and cheap enough to leave in a
 * hot path: a timer read and four stores, no formatting and no allocation. */
void sn_trace(uint8_t event, uint8_t arg8, uint16_t arg16);

/* Copies up to `max` entries oldest-first into `out`, returning how many.
 * Also reports how many events were recorded in total, so a caller can tell a
 * short trace from one that wrapped and lost its beginning. */
size_t sn_trace_read(sn_trace_entry_t *out, size_t max, uint32_t *total);

void sn_trace_clear(void);

/* Off by default: the cost is small but not zero, and a sniffer should not pay
 * it unless somebody is looking. */
void sn_trace_enable(bool on);
bool sn_trace_enabled(void);

#ifdef __cplusplus
}
#endif

#endif /* SN_TRACE_H */
