#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 2.4 GHz O-QPSK channels, the only ones this radio supports. */
#define SN_154_CHANNEL_MIN 11
#define SN_154_CHANNEL_MAX 26

/* Metadata prepended to every captured frame, 12 bytes, little-endian.
 * The host turns this into IEEE 802.15.4 TAP TLVs.
 *
 * The timestamp is NOT a hardware capture despite the driver's struct comment
 * claiming it marks the start-of-frame delimiter. The driver reads
 * esp_timer_get_time() inside its interrupt handler, so it carries interrupt
 * latency. Recorded because it is still the best available, but do not
 * describe it as hardware-timestamped. */
typedef struct __attribute__((packed)) {
    uint8_t channel;
    uint8_t lqi;
    int8_t rssi_dbm;
    uint8_t flags;      /* bit 0: PSDU includes the frame check sequence */
    uint64_t timestamp_us;
} sn_154_meta_t;

/* Currently never set. The radio substitutes signal strength and link quality
 * for the frame check sequence in the received buffer, so those two bytes are
 * dropped and no FCS reaches the host. Kept because the host honours it, and
 * a future radio or driver change could restore a real FCS. */
#define SN_154_FLAG_HAS_FCS 0x01u

/* Counters for losses nothing below us reports. The 802.15.4 driver's
 * "Rx buffer full" warning is compiled out unless CONFIG_IEEE802154_DEBUG is
 * set, so without these an overflow is completely invisible. */
typedef struct {
    uint32_t frames_captured;
    uint32_t isr_queue_full;   /* dropped in the receive interrupt */
    uint32_t link_rejected;    /* accepted here but refused by the USB link */
} sn_154_stats_t;

esp_err_t sn_radio154_start(uint8_t channel);
esp_err_t sn_radio154_set_channel(uint8_t channel);
void sn_radio154_stop(void);
uint8_t sn_radio154_channel(void);
void sn_radio154_get_stats(sn_154_stats_t *out);

/* Measures raw RF energy on `channel`, in dBm, and blocks until the radio
 * reports it. `duration_symbols` is in 16 us symbol periods.
 *
 * This sees energy rather than frames, which is the point: it detects the Wi-Fi
 * that overlaps most of the 2.4 GHz 802.15.4 channels, and works on a channel
 * carrying no decodable traffic at all. A capture can only tell you what was
 * transmitted while you happened to be listening; this tells you whether a
 * channel is usable. */
esp_err_t sn_radio154_energy_detect(uint8_t channel, uint32_t duration_symbols,
                                    int8_t *out_dbm);

#ifdef __cplusplus
}
#endif
