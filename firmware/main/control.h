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
    /* Power-gates the radio domain by way of a deep-sleep reset. See the
     * handler in main.c for why this exists and what it does not prove. */
    SN_CMD_RADIO_POWER_CYCLE = 11,
    SN_CMD_SET_BANDWIDTH = 12,   /* 0 = 20 MHz, 1 = HT40 above, 2 = HT40 below */
    SN_CMD_SET_CTRL_FILTER = 13, /* subtype mask for control frames */
    SN_CMD_SET_CSI = 14,         /* 0 = off, 1 = on */
    /* 1 if 802.15.4 has been used since boot, which leaves Wi-Fi deaf until
     * the radio domain is power-cycled. */
    SN_CMD_RADIO_DIRTY = 15,
    /* BLE scan window and interval, in milliseconds: interval in the low 16
     * bits, window in the high 16. Zero for either uses the default. */
    SN_CMD_SET_BLE_SCAN = 16,
    /* Primary advertising PHYs to scan: 0 forces legacy scanning, 1 is the
     * 1M PHY, 4 adds Coded (long range). */
    SN_CMD_SET_BLE_PHYS = 17,
    /* 1 puts the Wi-Fi driver in station mode while promiscuous capture
     * continues, which is what associating to an access point would need.
     * Espressif's sniffer examples all use WIFI_MODE_NULL, so whether the two
     * coexist is not documented anywhere and has to be measured. */
    SN_CMD_WIFI_STA_MODE = 18,
    SN_CMD_WIFI_CONNECT = 19,    /* associate using the credentials sent */
    SN_CMD_WIFI_DISCONNECT = 20,
    SN_CMD_SET_BLE_PERIODIC = 21, /* follow periodic advertising trains */
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

/* Called for a SN_FRAME_WIFI_CREDENTIALS frame. The payload is
 * ssid_len(1), ssid, pass_len(1), passphrase -- neither NUL terminated. */
typedef void (*sn_credentials_handler_t)(const uint8_t *payload, size_t len);
void sn_control_set_credentials_handler(sn_credentials_handler_t handler);

/* Starts the reader task. Call after sn_usb_link_init(). */
esp_err_t sn_control_start(void);

#ifdef __cplusplus
}
#endif
