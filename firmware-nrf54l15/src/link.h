#pragma once

#include <stddef.h>
#include <stdint.h>

#include "frame.h"

/* Brings up the UART the host reads, and starts the reader that feeds
 * sn_link_set_command_handler. Returns 0, or -ENODEV if the device is not
 * ready. */
int sn_link_init(void);

/* Frames a payload and writes it. Assigns the sequence number itself, so
 * nothing above this layer has to track one -- which is also why the host
 * matches command replies by echoed command id rather than by sequence.
 * Returns 0 on success. */
int sn_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len);

/* Called for the payload of each SN_FRAME_CONTROL_CMD that arrives. Runs on
 * the link's reader thread, never in an ISR, so it may block briefly. */
typedef void (*sn_command_handler_t)(const uint8_t *payload, size_t len);
void sn_link_set_command_handler(sn_command_handler_t handler);

/* Counters for the STATS frame. Kept here because this is the only place that
 * knows what actually reached the wire. */
uint32_t sn_link_frames_sent(void);
uint32_t sn_link_bytes_sent(void);
