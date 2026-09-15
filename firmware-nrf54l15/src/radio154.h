#pragma once

#include <stdint.h>

/* Mirrors sn_154_meta_t in firmware/main/radio154.h, which the host unpacks as
 * "<BBbBQ" in capture.py. Packed because the host reads it as a flat
 * little-endian struct with no padding, and a field that moves here decodes
 * into a confident wrong number there rather than an error. */
struct __attribute__((packed)) sn_154_meta {
	uint8_t  channel;
	uint8_t  lqi;
	int8_t   rssi_dbm;
	uint8_t  flags;
	uint64_t timestamp_us;
};

/* Binds the radio and configures it for sniffing. Must be called before
 * sn_radio154_start(). Returns 0 on success. */
int sn_radio154_init(void);

int sn_radio154_set_channel(uint8_t channel);
int sn_radio154_start(void);
int sn_radio154_stop(void);

uint8_t sn_radio154_channel(void);

/* Counters for the STATS frame. */
uint32_t sn_radio154_captured(void);
uint32_t sn_radio154_dropped(void);
