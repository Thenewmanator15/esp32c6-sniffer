#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Bluetooth Low Energy advertisement capture.
 *
 * WHAT THIS CAN AND CANNOT DO, because the difference matters and is easy to
 * misrepresent. The controller is driven in observer mode: it listens on the
 * three primary advertising channels and reports what it hears. That captures
 * advertisements, scan responses and the devices around you.
 *
 * It does NOT follow connections. A real BLE sniffer -- a dedicated one --
 * locks onto a connection request and hops the data channels with it. That
 * needs raw link-layer access this controller does not expose to an
 * application, so a connected device goes quiet here the moment it stops
 * advertising. Anyone needing connection capture wants a dedicated sniffer;
 * this is the advertising half, done honestly.
 *
 * Passive scanning only: the controller never transmits a scan request, so
 * the sniffer stays silent. That means scan responses appear only when some
 * other device solicits them, which is the trade for not announcing yourself.
 *
 * The controller runs WITHOUT a host stack. It is driven straight over HCI, so
 * what reaches the host is the controller's own HCI events, byte for byte, and
 * Wireshark dissects them with its own HCI dissector rather than anything
 * invented here.
 */

/* Metadata prepended to each forwarded HCI packet, 12 bytes, little-endian.
 * The HCI packet itself follows, starting with its H4 packet-type byte. */
typedef struct __attribute__((packed)) {
    uint64_t timestamp_us;  /* host clock at reception, from esp_timer */
    uint16_t orig_len;      /* HCI packet length before any truncation */
    uint8_t flags;
    uint8_t reserved;
} sn_ble_meta_t;

#define SN_BLE_FLAG_TRUNCATED 0x01u

/* Largest HCI packet forwarded. An extended advertising report can be long;
 * anything past this is truncated and flagged rather than dropped. */
#define SN_BLE_MAX_PACKET 300

typedef struct {
    uint32_t hci_packets;      /* HCI packets received from the controller */
    uint32_t adv_reports;      /* of those, LE advertising reports */
    uint32_t forwarded;
    uint32_t oversized;        /* truncated to SN_BLE_MAX_PACKET */
    uint32_t queue_full;
    uint32_t link_rejected;
    uint32_t command_timeouts; /* HCI setup steps that never completed */
    uint32_t periodic_seen;     /* advertisers announcing a periodic train */
    uint32_t periodic_synced;   /* syncs the controller established */
    uint32_t periodic_reports;  /* periodic advertising reports received */
} sn_ble_stats_t;

/* Brings up the controller and starts passive scanning.
 *
 * `window_ms` and `interval_ms` set the scan duty cycle. Equal values mean
 * continuous scanning on one advertising channel at a time, which is what a
 * sniffer wants; the controller rotates between the three channels itself.
 * Zero for either uses the default. */
esp_err_t sn_radio_ble_start(uint16_t interval_ms, uint16_t window_ms);

/* Stops scanning and releases the radio.
 *
 * Not merely disabling the scan: the controller is disabled and deinitialised
 * so the shared 2.4 GHz front end goes back. Leaving the 802.15.4 radio
 * enabled leaves the Wi-Fi receiver deaf until the RF domain is power-gated,
 * and there is no reason to assume this radio is kinder. */
void sn_radio_ble_stop(void);

bool sn_radio_ble_running(void);
void sn_radio_ble_get_stats(sn_ble_stats_t *out);

/* Primary advertising PHYs a scan may use. 2M is deliberately absent: primary
 * advertising never uses it, and including it makes the controller reject the
 * whole scan configuration. */
#define SN_BLE_PHY_LEGACY_ONLY 0x00
#define SN_BLE_PHY_1M    0x01
#define SN_BLE_PHY_CODED 0x04

/* True if the running scan is the extended kind, which is the only one that
 * reports BLE 5 extended advertisements. */
bool sn_radio_ble_extended(void);

/* Selects which primary PHYs to scan. Adding Coded (long range) costs 1M
 * coverage, because the controller time-shares between them. */
esp_err_t sn_radio_ble_set_phys(uint8_t phys);

/* Follows periodic advertising trains.
 *
 * A periodic advertiser announces its train in an extended advertisement, and
 * the contents are only visible after synchronising to it. This is how LE
 * Audio and Auracast broadcasts are found: the broadcast audio stream is
 * carried by a periodic train, not by ordinary advertisements.
 *
 * Syncing costs radio time that would otherwise be spent scanning, so it is
 * off by default and capped at a small number of concurrent syncs. */
esp_err_t sn_radio_ble_set_periodic(bool enable);

#define SN_BLE_DEFAULT_INTERVAL_MS 60
#define SN_BLE_DEFAULT_WINDOW_MS   60

#ifdef __cplusplus
}
#endif
