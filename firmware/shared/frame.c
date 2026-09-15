#include "frame.h"

#include <string.h>

uint16_t sn_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= (uint16_t)((uint16_t)data[i] << 8);
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 0x8000u) ? (uint16_t)((uint16_t)(crc << 1) ^ 0x1021u)
                                  : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

size_t sn_frame_encode(uint8_t *out, size_t out_cap, sn_frame_type_t type,
                       uint16_t seq, const uint8_t *payload, size_t payload_len)
{
    if (payload_len > SN_MAX_PAYLOAD) {
        return 0;
    }
    if (out_cap < SN_HEADER_LEN + payload_len) {
        return 0;
    }

    out[0] = (uint8_t)(SN_MAGIC & 0xFFu);
    out[1] = (uint8_t)((SN_MAGIC >> 8) & 0xFFu);
    out[2] = (uint8_t)type;
    out[3] = 0u; /* flags, reserved */
    out[4] = (uint8_t)(seq & 0xFFu);
    out[5] = (uint8_t)((seq >> 8) & 0xFFu);
    out[6] = (uint8_t)(payload_len & 0xFFu);
    out[7] = (uint8_t)((payload_len >> 8) & 0xFFu);

    const uint16_t crc = sn_crc16(out, 8);
    out[8] = (uint8_t)(crc & 0xFFu);
    out[9] = (uint8_t)((crc >> 8) & 0xFFu);

    if (payload_len > 0 && payload != NULL) {
        memcpy(out + SN_HEADER_LEN, payload, payload_len);
    }
    return SN_HEADER_LEN + payload_len;
}
