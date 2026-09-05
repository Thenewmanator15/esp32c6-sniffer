#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "frame.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Counters for things nothing else reports.
 *
 * Neither radio driver exposes a drop count: Espressif proposed a Wi-Fi
 * promiscuous overflow counter and closed the issue without adding one, and
 * the 802.15.4 "Rx buffer full" warning is compiled out in default builds.
 * Without our own numbers there is no way to tell a quiet channel from a
 * broken pipeline. */
typedef struct {
    uint32_t frames_sent;
    uint32_t frames_dropped_ringfull;
    uint32_t short_writes;
    uint32_t tx_stalls;
    uint32_t bytes_sent;
} sn_link_stats_t;

esp_err_t sn_usb_link_init(void);

/* Encodes and queues one frame, assigning the sequence number internally.
 * Returns false if the ring buffer was full and the frame was dropped.
 * Safe to call from multiple tasks. Not safe from an ISR. */
bool sn_usb_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len);

void sn_usb_link_get_stats(sn_link_stats_t *out);

#ifdef __cplusplus
}
#endif
