#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wire format mirrors host/src/esp32c6_sniffer/framing.py, which is the
 * authoritative definition. Byte-identity is enforced by the golden vectors in
 * host/tests/vectors/golden.json.
 *
 * Header is 10 bytes, little-endian:
 *   0  2  magic 0x5AC6
 *   2  1  type
 *   3  1  flags (reserved, 0)
 *   4  2  seq
 *   6  2  payload length
 *   8  2  CRC-16/CCITT-FALSE over bytes 0..7
 */

#define SN_MAGIC        0x5AC6u
#define SN_HEADER_LEN   10u
#define SN_MAX_PAYLOAD  4096u

typedef enum {
    SN_FRAME_PACKET = 1,
    SN_FRAME_LOG = 2,
    SN_FRAME_STATS = 3,
    SN_FRAME_HEARTBEAT = 4,
    SN_FRAME_CONTROL_REPLY = 5,
    SN_FRAME_CONTROL_CMD = 6,
    /* One access point from a Wi-Fi scan. Sent as its own frame rather than
     * packed into the command reply, because the list is variable length and
     * a reply carries a single 32-bit value. */
    SN_FRAME_AP_RECORD = 7,
    /* Channel state information for one received frame: the per-subcarrier
     * channel response, which no pcap link type has a place for, so it travels
     * beside the capture rather than inside it. */
    SN_FRAME_CSI = 8,
    /* Host to board: a network name and passphrase, for associating so an
     * access point will speak 11ax to this radio. Kept in RAM only and never
     * logged; the Wi-Fi driver is already configured for RAM storage so it
     * never reaches flash either. */
    SN_FRAME_WIFI_CREDENTIALS = 9,
} sn_frame_type_t;

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no final XOR.
 *
 * Implemented here rather than using esp_rom_crc16_le, whose reflection and
 * final-XOR behaviour would have to be matched exactly on the host side. The
 * ESP32-C6 has no CRC peripheral, so the ROM routines are software table
 * lookups anyway. Over an 8-byte header this is 64 iterations. */
uint16_t sn_crc16(const uint8_t *data, size_t len);

/* Writes a complete frame into `out`. Returns bytes written, or 0 if the
 * payload is too large or the buffer too small. */
size_t sn_frame_encode(uint8_t *out, size_t out_cap, sn_frame_type_t type,
                       uint16_t seq, const uint8_t *payload, size_t payload_len);

#ifdef __cplusplus
}
#endif
