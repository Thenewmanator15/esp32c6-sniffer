#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Commands from the host. Must match Command in
 * host/src/esp32c6_sniffer/control.py. */
typedef enum {
    SN_CMD_SET_CHANNEL = 1,
    SN_CMD_SET_ANTENNA = 2,
    SN_CMD_START = 3,
    SN_CMD_STOP = 4,
    SN_CMD_GET_INFO = 5,
    SN_CMD_ENERGY_DETECT = 6,
    SN_CMD_SET_RADIO = 7,
    SN_CMD_WIFI_SCAN = 8,
    SN_CMD_SET_SNAPLEN = 9,
    SN_CMD_SET_FILTER = 10,
} sn_command_t;

/* Status codes returned in a reply. 0 means success. */
typedef enum {
    SN_STATUS_OK = 0,
    SN_STATUS_UNKNOWN_COMMAND = 1,
    SN_STATUS_BAD_VALUE = 2,
    SN_STATUS_FAILED = 3,
} sn_status_t;

/* Handles one command. Write any returned value through `out_value`, which is
 * pre-set to 0. Runs on the control task, never in an ISR, so it may block
 * briefly but should not do lengthy work. */
typedef sn_status_t (*sn_control_handler_t)(sn_command_t cmd, uint32_t value,
                                            uint32_t *out_value);

void sn_control_set_handler(sn_control_handler_t handler);

/* Starts the reader task. Call after sn_usb_link_init(). */
esp_err_t sn_control_start(void);

#ifdef __cplusplus
}
#endif
