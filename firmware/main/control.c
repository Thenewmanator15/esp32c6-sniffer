#include "control.h"

#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "esp_log.h"
#include "frame.h"
#include "trace.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "usb_link.h"

static const char *TAG = "control";

/* Inbound frames are tiny (a 10-byte header plus a 5-byte payload), so a small
 * buffer suffices. Sized for a few frames plus slack for resynchronisation. */
#define RX_BUF_LEN      128
#define READ_CHUNK      64
#define CMD_PAYLOAD_LEN 5
#define REPLY_LEN       6

static sn_control_handler_t s_handler;
static sn_credentials_handler_t s_credentials_handler;
static sn_ble_filter_handler_t s_ble_filter_handler;
static uint8_t s_buf[RX_BUF_LEN];
static size_t s_len;

void sn_control_set_handler(sn_control_handler_t handler)
{
    s_handler = handler;
}

static void send_reply(uint8_t cmd, uint8_t status, uint32_t value)
{
    uint8_t payload[REPLY_LEN];
    payload[0] = cmd;
    payload[1] = status;
    payload[2] = (uint8_t)(value & 0xFFu);
    payload[3] = (uint8_t)((value >> 8) & 0xFFu);
    payload[4] = (uint8_t)((value >> 16) & 0xFFu);
    payload[5] = (uint8_t)((value >> 24) & 0xFFu);
    sn_usb_link_send(SN_FRAME_CONTROL_REPLY, payload, sizeof(payload));
}

static void dispatch(const uint8_t *payload, size_t len)
{
    if (len < CMD_PAYLOAD_LEN) {
        return;
    }
    const uint8_t cmd = payload[0];
    const uint32_t value = (uint32_t)payload[1] |
                           ((uint32_t)payload[2] << 8) |
                           ((uint32_t)payload[3] << 16) |
                           ((uint32_t)payload[4] << 24);

    uint32_t out_value = 0;
    sn_status_t status = SN_STATUS_UNKNOWN_COMMAND;
    /* Bracketed, so the trace shows how long a command took rather than only
     * when it arrived. A command that blocks for a second is invisible from
     * the host, which sees one round trip and cannot say which side spent it. */
    sn_trace(SN_TRACE_CMD_IN, cmd, 0);
    if (s_handler != NULL) {
        status = s_handler((sn_command_t)cmd, value, &out_value);
    }
    sn_trace(SN_TRACE_CMD_OUT, cmd, (uint16_t)status);
    send_reply(cmd, (uint8_t)status, out_value);
}

/* Consumes whole frames from the head of s_buf, discarding leading garbage.
 *
 * Mirrors the host parser deliberately: the host discards bytes when this board
 * stops draining, and the same can happen in reverse, so neither end may assume
 * it is looking at a frame boundary. */
static void parse_buffered(void)
{
    while (s_len >= SN_HEADER_LEN) {
        /* Find a plausible frame start. */
        if (!(s_buf[0] == (uint8_t)(SN_MAGIC & 0xFFu) &&
              s_buf[1] == (uint8_t)((SN_MAGIC >> 8) & 0xFFu))) {
            memmove(s_buf, s_buf + 1, --s_len);
            continue;
        }

        const uint16_t want_crc = (uint16_t)s_buf[8] |
                                  (uint16_t)((uint16_t)s_buf[9] << 8);
        if (sn_crc16(s_buf, 8) != want_crc) {
            /* Magic matched by chance inside other data. */
            memmove(s_buf, s_buf + 1, --s_len);
            continue;
        }

        const uint16_t payload_len = (uint16_t)s_buf[6] |
                                     (uint16_t)((uint16_t)s_buf[7] << 8);
        if (payload_len > RX_BUF_LEN - SN_HEADER_LEN) {
            /* Cannot ever fit: treat the header as spurious rather than
             * stalling forever waiting for a payload we have no room for. */
            memmove(s_buf, s_buf + 1, --s_len);
            continue;
        }
        const size_t total = SN_HEADER_LEN + payload_len;
        if (s_len < total) {
            return; /* wait for the rest */
        }

        if (s_buf[2] == SN_FRAME_CONTROL_CMD) {
            dispatch(s_buf + SN_HEADER_LEN, payload_len);
        } else if (s_buf[2] == SN_FRAME_WIFI_CREDENTIALS &&
                   s_credentials_handler != NULL) {
            s_credentials_handler(s_buf + SN_HEADER_LEN, payload_len);
        } else if (s_buf[2] == SN_FRAME_BLE_FILTER &&
                   s_ble_filter_handler != NULL) {
            s_ble_filter_handler(s_buf + SN_HEADER_LEN, payload_len);
        }
        memmove(s_buf, s_buf + total, s_len - total);
        s_len -= total;
    }
}

void sn_control_set_credentials_handler(sn_credentials_handler_t handler)
{
    s_credentials_handler = handler;
}

void sn_control_set_ble_filter_handler(sn_ble_filter_handler_t handler)
{
    s_ble_filter_handler = handler;
}

static void control_task(void *arg)
{
    (void)arg;
    uint8_t chunk[READ_CHUNK];

    while (true) {
        const int n = usb_serial_jtag_read_bytes(chunk, sizeof(chunk),
                                                 pdMS_TO_TICKS(100));
        if (n <= 0) {
            continue;
        }
        size_t room = RX_BUF_LEN - s_len;
        if ((size_t)n > room) {
            /* Buffer full of unparseable bytes. Drop the oldest half rather
             * than wedging: a command is small, so anything this old is junk. */
            const size_t drop = RX_BUF_LEN / 2;
            memmove(s_buf, s_buf + drop, s_len - drop);
            s_len -= drop;
            room = RX_BUF_LEN - s_len;
            ESP_LOGW(TAG, "control buffer overrun, dropped %u bytes",
                     (unsigned)drop);
        }
        const size_t take = ((size_t)n < room) ? (size_t)n : room;
        memcpy(s_buf + s_len, chunk, take);
        s_len += take;
        parse_buffered();
    }
}

esp_err_t sn_control_start(void)
{
    if (xTaskCreate(control_task, "sn_ctrl", 4096, NULL, 8, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
