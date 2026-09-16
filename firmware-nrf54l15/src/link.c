#include "link.h"

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>
#include <zephyr/devicetree.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/ring_buffer.h>

/* The SoC has no USB device controller, so the host is reached through the
 * board's SAMD11 running CMSIS-DAP, which bridges this UART to a USB CDC port.
 *
 * Three things were measured on that path and all three are load-bearing here.
 * See docs/2026-09-14-nrf54l15-spike.md.
 *
 * The UARTE is capped at 1 Mbaud -- silicon, not configuration -- so ~100 kB/s
 * of line rate is the ceiling for anything reaching the USB-C socket. The
 * board's default of 115200 carries 11.7 kB/s against the ~31 kB/s an 802.15.4
 * channel can produce, so the default was not merely slow, it was
 * insufficient. And uart_poll_out() polls a register per byte, which reached
 * only 78% of line rate and, worse, blocks its caller: at 115200 a 130-byte
 * frame holds the radio driver's RX thread for about 11 ms.
 *
 * So frames are encoded into a ring buffer and a separate thread hands whole
 * spans to EasyDMA. sn_link_send() now returns as soon as the bytes are
 * queued, which keeps the radio's receive path moving, and the DMA reaches
 * 94% of line rate instead of 78%.
 */
static const struct device *const uart = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

static uint16_t seq;
static uint32_t frames_sent;
static uint32_t bytes_sent;
static uint32_t frames_dropped;

/* Outbound bytes waiting for DMA. Sized for roughly a tenth of a second at
 * 1 Mbaud, which covers a burst without letting a stalled host buffer
 * unboundedly: a sniffer that hoards stale frames is worse than one that says
 * it dropped some. */
#define TX_RING_SIZE 8192
RING_BUF_DECLARE(tx_ring, TX_RING_SIZE);
static K_SEM_DEFINE(tx_ready, 0, 1);
static K_SEM_DEFINE(tx_done, 1, 1);
static K_MUTEX_DEFINE(encode_lock);

/* Staging for one encoded frame before it enters the ring. */
static uint8_t scratch[SN_HEADER_LEN + SN_MAX_PAYLOAD];

/* Host to board. Commands are five bytes, so this only ever needs to hold a
 * frame or two. */
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

static void uart_cb(const struct device *dev, struct uart_event *evt, void *user_data)
{
	ARG_UNUSED(dev);
	ARG_UNUSED(user_data);

	switch (evt->type) {
	case UART_TX_DONE:
	case UART_TX_ABORTED:
		k_sem_give(&tx_done);
		break;

	case UART_RX_RDY:
		/* A full ring drops the byte rather than blocking in a
		 * callback. The frame it belonged to then fails its header CRC
		 * and is resynchronised past, which is the same recovery the
		 * host's parser makes on a lost byte. */
		ring_buf_put(&rx_ring, evt->data.rx.buf + evt->data.rx.offset,
			     evt->data.rx.len);
		break;

	default:
		break;
	}
}

/* Double-buffered receive, so the driver always has somewhere to put bytes. */
static uint8_t rx_dma[2][64];
static int rx_dma_next;

static void uart_cb_rx(const struct device *dev, struct uart_event *evt, void *user_data)
{
	uart_cb(dev, evt, user_data);

	if (evt->type == UART_RX_BUF_REQUEST) {
		uart_rx_buf_rsp(dev, rx_dma[rx_dma_next], sizeof(rx_dma[0]));
		rx_dma_next ^= 1;
	}
}

/* The SAMD11 bridge overruns during long uninterrupted runs at 1 Mbaud.
 * Measured: 9 bytes lost, twice, both mid-way through the 266-byte
 * conformance frame, and none in a second identical run -- about 90 us of
 * the bridge not draining. Per-byte uart_poll_out never showed it because it
 * left gaps between bytes by accident; EasyDMA streams at exactly line rate
 * and removed them. So each DMA transfer is capped and followed by a short,
 * deliberate gap. At 64 bytes and 20 us that costs about 3% of line rate,
 * against a bridge that otherwise drops a frame every so often. Both are
 * tunables, and both were arrived at by measurement, not taste. */
#define TX_DMA_CHUNK  64
#define TX_DMA_GAP_US 20

static void tx_thread(void *a, void *b, void *c)
{
	ARG_UNUSED(a);
	ARG_UNUSED(b);
	ARG_UNUSED(c);

	while (true) {
		uint8_t *span;
		const uint32_t n = ring_buf_get_claim(&tx_ring, &span, TX_DMA_CHUNK);

		if (n == 0u) {
			ring_buf_get_finish(&tx_ring, 0);
			k_sem_take(&tx_ready, K_FOREVER);
			continue;
		}
		k_sem_take(&tx_done, K_FOREVER);
		if (uart_tx(uart, span, n, SYS_FOREVER_US) != 0) {
			k_sem_give(&tx_done);
			ring_buf_get_finish(&tx_ring, 0);
			k_sleep(K_MSEC(1));
			continue;
		}
		/* Wait for the DMA before releasing the span: the ring must not
		 * hand these bytes out again while the peripheral is reading
		 * them. */
		k_sem_take(&tx_done, K_FOREVER);
		k_sem_give(&tx_done);
		ring_buf_get_finish(&tx_ring, n);

		/* The breath the bridge needs. See the comment above. */
		k_busy_wait(TX_DMA_GAP_US);
	}
}

K_THREAD_DEFINE(sn_link_tx, 1024, tx_thread, NULL, NULL, NULL, 6, 0, 0);

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
	if (uart_callback_set(uart, uart_cb_rx, NULL) != 0) {
		return -ENOTSUP;
	}
	rx_dma_next = 1;
	(void)uart_rx_enable(uart, rx_dma[0], sizeof(rx_dma[0]), 1000);
	return 0;
}

int sn_link_send(sn_frame_type_t type, const uint8_t *payload, size_t len)
{
	k_mutex_lock(&encode_lock, K_FOREVER);

	const size_t n = sn_frame_encode(scratch, sizeof(scratch), type, seq,
					 payload, len);
	if (n == 0u) {
		k_mutex_unlock(&encode_lock);
		return -EINVAL;
	}

	/* All or nothing. Half a frame in the ring would be indistinguishable
	 * from a corrupted one at the host, and would cost it a resync for no
	 * reason; a frame refused outright is counted and reported instead. */
	if (ring_buf_space_get(&tx_ring) < n) {
		frames_dropped++;
		k_mutex_unlock(&encode_lock);
		return -ENOMEM;
	}
	seq++;
	ring_buf_put(&tx_ring, scratch, n);
	frames_sent++;
	bytes_sent += (uint32_t)n;

	k_mutex_unlock(&encode_lock);
	k_sem_give(&tx_ready);
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

uint32_t sn_link_frames_dropped(void)
{
	return frames_dropped;
}
