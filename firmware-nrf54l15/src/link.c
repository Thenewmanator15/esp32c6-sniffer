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
 * rate is not merely slow here, it is insufficient, and raising it is a
 * measurement this firmware has not yet earned the right to assume.
 *
 * It is left at the board's default for now because that is what the host's
 * conftest opens the port at, and the conformance burst fits comfortably.
 */
static const struct device *const uart = DEVICE_DT_GET(DT_CHOSEN(zephyr_console));

static uint16_t seq;
static uint32_t frames_sent;
static uint32_t bytes_sent;
static uint8_t out[SN_HEADER_LEN + SN_MAX_PAYLOAD];

/* sn_link_send may be called from more than one context once there is a radio
 * and a control channel, and `out` and `seq` are shared. */
K_MUTEX_DEFINE(link_lock);

int sn_link_init(void)
{
	return device_is_ready(uart) ? 0 : -ENODEV;
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
