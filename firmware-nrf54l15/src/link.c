#include "link.h"

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>

/* The SoC has no USB device controller, so the host is reached through the
 * board's SAMD11 running CMSIS-DAP, which bridges this UART to a USB CDC port.
 * That bridge, not the radio, is the narrowest part of the system: the C6
 * reaches ~810 kB/s over native USB, and uart20 defaults to 115200 baud, which
 * is about 11.5 kB/s. An 802.15.4 channel can produce ~31 kB/s, so the default
 * rate is not merely slow here, it is insufficient for a busy channel, and
 * raising it is a measurement this firmware has not yet earned the right to
 * assume. It is left at the board default because that is what the host's
 * conftest opens the port at.
 */
static const struct device *const uart = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

static uint16_t seq;
static uint32_t frames_sent;
static uint32_t bytes_sent;
static uint8_t out[SN_HEADER_LEN + SN_MAX_PAYLOAD];

/* sn_link_send is called from the radio's receive path, from the stats timer
 * and from the control handler, and `out` and `seq` are shared. */
K_MUTEX_DEFINE(link_lock);

/* Host to board. Commands are five bytes, so this only ever needs to hold a
 * frame or two; it is sized for comfort rather than need. */
#define RX_RING_SIZE 512
RING_BUF_DECLARE(rx_ring, RX_RING_SIZE);

static sn_command_handler_t command_handler;

/* Reassembly buffer for the reader thread. A control frame is 15 bytes; the
 * headroom is for anything the host adds later. */
static uint8_t rx_buf[256];
static size_t rx_len;

void sn_link_set_command_handler(sn_command_handler_t handler)
{
	command_handler = handler;
}

static void uart_isr(const struct device *dev, void *user_data)
{
	ARG_UNUSED(user_data);

	while (uart_irq_update(dev) && uart_irq_is_pending(dev)) {
		if (!uart_irq_rx_ready(dev)) {
			continue;
		}
		uint8_t byte;
		while (uart_fifo_read(dev, &byte, 1) == 1) {
			/* A full ring drops the byte rather than blocking in an
			 * ISR. The frame it belonged to then fails its header
			 * CRC and is resynchronised past, which is the same
			 * recovery the host's parser makes on a lost byte. */
			ring_buf_put(&rx_ring, &byte, 1);
		}
	}
}

/* Consumes whole frames from rx_buf, dispatching the ones we handle.
 *
 * Resynchronisation is by magic and header CRC, exactly as the host's
 * StreamParser does it: a byte lost in either direction must cost one frame,
 * not the rest of the session. */
static void drain(void)
{
	size_t at = 0;

	while (rx_len - at >= SN_HEADER_LEN) {
		const uint8_t *p = rx_buf + at;
		const uint16_t magic = (uint16_t)p[0] | ((uint16_t)p[1] << 8);

		if (magic != SN_MAGIC) {
			at++;
			continue;
		}
		const uint16_t want_crc = (uint16_t)p[8] | ((uint16_t)p[9] << 8);
		if (sn_crc16(p, 8) != want_crc) {
			at++;
			continue;
		}
		const uint16_t len = (uint16_t)p[6] | ((uint16_t)p[7] << 8);
		if (len > SN_MAX_PAYLOAD) {
			at++;
			continue;
		}
		if (rx_len - at < SN_HEADER_LEN + (size_t)len) {
			break;      /* the rest is still in flight */
		}
		if (p[2] == (uint8_t)SN_FRAME_CONTROL_CMD && command_handler != NULL) {
			command_handler(p + SN_HEADER_LEN, len);
		}
		at += SN_HEADER_LEN + len;
	}

	if (at > 0) {
		memmove(rx_buf, rx_buf + at, rx_len - at);
		rx_len -= at;
	}
	/* Nothing decodable and no room left means the buffer is full of
	 * rubbish. Keeping the tail preserves a frame that merely straddles
	 * the end. */
	if (rx_len == sizeof(rx_buf)) {
		memmove(rx_buf, rx_buf + sizeof(rx_buf) - SN_HEADER_LEN,
			SN_HEADER_LEN);
		rx_len = SN_HEADER_LEN;
	}
}

static void reader(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	while (true) {
		uint8_t chunk[64];
		const uint32_t n = ring_buf_get(&rx_ring, chunk, sizeof(chunk));

		if (n == 0u) {
			k_sleep(K_MSEC(2));
			continue;
		}
		const size_t room = sizeof(rx_buf) - rx_len;
		const size_t take = n < room ? n : room;

		memcpy(rx_buf + rx_len, chunk, take);
		rx_len += take;
		drain();
	}
}

K_THREAD_DEFINE(sn_link_reader, 1024, reader, NULL, NULL, NULL, 7, 0, 0);

int sn_link_init(void)
{
	if (!device_is_ready(uart)) {
		return -ENODEV;
	}
	uart_irq_callback_user_data_set(uart, uart_isr, NULL);
	uart_irq_rx_enable(uart);
	return 0;
}

int sn_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len)
{
	k_mutex_lock(&link_lock, K_FOREVER);

	const size_t n = sn_frame_encode(out, sizeof(out), type, seq, payload, len);
	if (n == 0u) {
		k_mutex_unlock(&link_lock);
		return -EINVAL;
	}
	seq++;

	for (size_t i = 0; i < n; i++) {
		uart_poll_out(uart, out[i]);
	}
	frames_sent++;
	bytes_sent += (uint32_t)n;

	k_mutex_unlock(&link_lock);
	return 0;
}

uint32_t sn_link_frames_sent(void)
{
	return frames_sent;
}

uint32_t sn_link_bytes_sent(void)
{
	return bytes_sent;
}
