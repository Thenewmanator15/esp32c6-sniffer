#pragma once

#include <stddef.h>
#include <stdint.h>

/* Handles the payload of one SN_FRAME_CONTROL_CMD and replies. Registered with
 * sn_link_set_command_handler, so it runs on the link's reader thread. */
void sn_control_handle(const uint8_t *payload, size_t len);

/* Provided by main.c, so control.c need not see the build-mode macros. */
uint32_t sn_firmware_version(void);
