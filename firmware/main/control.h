#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

/* Command and status numbers, shared with the nRF54L15 firmware. */
#include "commands.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/* Called for a SN_FRAME_BLE_FILTER frame. The payload is N repetitions of
 * one address-type byte and six address bytes, least significant first as
 * HCI carries them. An empty payload means scan everything again. */
typedef void (*sn_ble_filter_handler_t)(const uint8_t *payload, size_t len);
void sn_control_set_ble_filter_handler(sn_ble_filter_handler_t handler);

/* Starts the reader task. Call after sn_usb_link_init(). */
esp_err_t sn_control_start(void);

#ifdef __cplusplus
}
#endif
