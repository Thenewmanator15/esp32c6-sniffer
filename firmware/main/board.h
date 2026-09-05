#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Seeed XIAO ESP32-C6 RF path.
 *
 * GPIO3  drives the gate of a P-FET (Q3) supplying the FM8625H RF switch.
 *        It is pulled up at reset, so the switch is UNPOWERED on boot and the
 *        radio reaches its antenna only through roughly 30 dB of leakage.
 *        Driving it LOW powers the switch. This is not optional, and it is
 *        required for BOTH antennas.
 * GPIO14 is the switch's VCTL: 0 selects the onboard ceramic antenna (RF1),
 *        1 selects the external U.FL connector (RF2).
 *
 * Both pins are internal-only on this board, conflict with nothing on the
 * headers, and must be HELD, not pulsed.
 *
 * The Arduino core does this at boot, so the problem never surfaces there.
 * Seeed's own ESP-IDF documentation does not mention the antenna switch at all.
 */
#define SN_PIN_RF_SWITCH_PWR 3
#define SN_PIN_ANTENNA_SEL   14

typedef enum {
    SN_ANTENNA_INTERNAL = 0,
    SN_ANTENNA_EXTERNAL = 1,
} sn_antenna_t;

/* Powers the RF switch and selects an antenna.
 * Must be called before enabling any radio. */
esp_err_t sn_board_init(sn_antenna_t antenna);

#ifdef __cplusplus
}
#endif
