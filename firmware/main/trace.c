#include "trace.h"

#include <string.h>

#include "freertos/FreeRTOS.h"

/* IRAM, because the RX interrupt records into this and a cache miss on the
 * ring would show up as jitter in the very measurement it exists to make. */
static DRAM_ATTR sn_trace_entry_t s_ring[SN_TRACE_SLOTS];
static DRAM_ATTR volatile uint32_t s_next;      /* monotonic; masked on use */
static DRAM_ATTR volatile bool s_on;

void IRAM_ATTR sn_trace(uint8_t event, uint8_t arg8, uint16_t arg16)
{
    if (!s_on) {
        return;
    }
    /* Claimed without a lock. Two writers can collide and one entry is then
     * lost or written twice; a critical section here would serialise the
     * interrupt against the task and change the timing this is measuring,
     * which is a worse trade for diagnostic data. */
    const uint32_t slot = s_next++;
    sn_trace_entry_t *entry = &s_ring[slot & (SN_TRACE_SLOTS - 1u)];
    entry->us = (uint32_t)esp_timer_get_time();
    entry->event = event;
    entry->arg8 = arg8;
    entry->arg16 = arg16;
}

size_t sn_trace_read(sn_trace_entry_t *out, size_t max, uint32_t *total)
{
    const uint32_t written = s_next;
    if (total != NULL) {
        *total = written;
    }
    if (out == NULL || max == 0u) {
        return 0u;
    }

    /* Oldest first. Once more than SN_TRACE_SLOTS events have been recorded
     * the ring has wrapped and the oldest surviving entry is the one after
     * the newest, not slot zero. */
    const uint32_t have = (written < SN_TRACE_SLOTS) ? written : SN_TRACE_SLOTS;
    const uint32_t take = (have < max) ? have : (uint32_t)max;
    const uint32_t first = written - have;

    for (uint32_t i = 0; i < take; i++) {
        out[i] = s_ring[(first + i) & (SN_TRACE_SLOTS - 1u)];
    }
    return take;
}

void sn_trace_clear(void)
{
    s_next = 0;
    memset(s_ring, 0, sizeof(s_ring));
}

void sn_trace_enable(bool on)
{
    if (on && !s_on) {
        sn_trace_clear();
    }
    s_on = on;
}

bool sn_trace_enabled(void)
{
    return s_on;
}
