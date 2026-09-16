/* The XIAO nRF54L15 half of the sniffer.
 *
 * Speaks the same wire format as the ESP32-C6 firmware, by compiling the same
 * frame.c rather than reimplementing it. See firmware/shared/frame.h.
 */

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "control.h"
#include "frame.h"
#include "link.h"
#include "radio154.h"

/* Wire format this firmware speaks. Must match the nrf54l15 entry in
 * EXPECTED_FIRMWARE_VERSIONS in host/src/esp32c6_sniffer/capture.py; the host
 * refuses to open a capture until the two agree, because an older board packs
 * its metadata differently and every field would then decode to a confident
 * wrong number rather than an error. */
#define SN_FIRMWARE_VERSION 1u

LOG_MODULE_REGISTER(sniffer, LOG_LEVEL_INF);

#ifndef SN_MODE
#define SN_MODE 0
#endif

#define SN_MODE_CONFORMANCE 0
#define SN_MODE_CAPTURE     2

uint32_t sn_firmware_version(void)
{
	return SN_FIRMWARE_VERSION;
}

#if SN_MODE == SN_MODE_CONFORMANCE
/* The same burst firmware/main/main.c emits, in the same order, so the host's
 * existing conformance test holds BOTH boards to one set of vectors without
 * knowing there is more than one board. Payloads are transcribed from
 * host/tests/vectors/golden.json; the sequence numbers are assigned by the
 * link at runtime, which is why the host compares types and payloads and then
 * re-encodes to check the bytes. */
static void conformance_burst(void)
{
	static uint8_t all_bytes[256];

	for (int i = 0; i < 256; i++) {
		all_bytes[i] = (uint8_t)i;
	}
	static const uint8_t newline_bytes[] = {0x0a, 0x0d, 0x0a, 0x00, 0xff};
	static const char hello[] = "hello";
	static const char wrap[] = "wrap";
	static const char logmsg[] = "I (123) tag: msg";
	/* A three-entry batch on channel 25 -- base 1000000 us, deltas 0/450/2550,
	 * the last entry a real acknowledgement -- and a ring 48000 bytes deep
	 * with a 128 KB high-water mark of 192 KB capacity. Transcribed from
	 * host/tests/vectors/golden.json; the layouts are authoritative in
	 * host/src/esp32c6_sniffer/batch.py. */
	static const uint8_t batch_three[] = {
		0x40, 0x42, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19, 0x03,
		0x00, 0x00, 0xc8, 0xc4, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
		0xc2, 0x01, 0xc7, 0xc3, 0x05, 0x0a, 0x0d, 0x0a, 0x00, 0xff,
		0xf6, 0x09, 0x00, 0x9e, 0x05, 0x02, 0x00, 0x1e, 0x00, 0xf2,
	};
	static const uint8_t link_status[] = {
		0x80, 0xbb, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00,
	};

	while (true) {
		sn_link_send(SN_FRAME_HEARTBEAT, NULL, 0);
		sn_link_send(SN_FRAME_PACKET, (const uint8_t *)hello, sizeof(hello) - 1);
		sn_link_send(SN_FRAME_PACKET, newline_bytes, sizeof(newline_bytes));
		sn_link_send(SN_FRAME_PACKET, all_bytes, sizeof(all_bytes));
		sn_link_send(SN_FRAME_PACKET, (const uint8_t *)wrap, sizeof(wrap) - 1);
		sn_link_send(SN_FRAME_LOG, (const uint8_t *)logmsg, sizeof(logmsg) - 1);
		/* PACKET_BATCH and LINK, identical bytes to firmware/main/main.c and
		 * to golden.json, in the same position in the burst. */
		sn_link_send(SN_FRAME_PACKET_BATCH, batch_three, sizeof(batch_three));
		sn_link_send(SN_FRAME_LINK, link_status, sizeof(link_status));
		k_sleep(K_MSEC(500));
	}
}
#endif

#if SN_MODE == SN_MODE_CAPTURE
/* Published once a second, in the short form of the stats payload the host
 * already decodes: five link counters then three for the radio, as
 * sn_link_stats_t and sn_154_stats_t are laid out in the ESP-IDF firmware.
 * The host reads it as "<8I" and zero-fills the Wi-Fi counters it knows this
 * board does not have.
 *
 * frames_dropped_ringfull is now a real measurement: the outbound ring can
 * fill if the host stops draining, and a frame refused at that point is loss
 * the operator should be told about. The rest stay zero deliberately -- this
 * link does not detect short writes or transmit stalls, so reporting anything
 * but zero for those would invent a measurement. */
struct __attribute__((packed)) sn_stats_short {
	uint32_t frames_sent;
	uint32_t frames_dropped_ringfull;
	uint32_t short_writes;
	uint32_t tx_stalls;
	uint32_t bytes_sent;
	uint32_t frames_captured;
	uint32_t isr_queue_full;
	uint32_t link_rejected;
};

static void stats_tick(struct k_work *work);
static K_WORK_DELAYABLE_DEFINE(stats_work, stats_tick);

static void stats_tick(struct k_work *work)
{
	ARG_UNUSED(work);

	const struct sn_stats_short stats = {
		.frames_sent = sn_link_frames_sent(),
		.frames_dropped_ringfull = sn_link_frames_dropped(),
		.short_writes = 0u,
		.tx_stalls = 0u,
		.bytes_sent = sn_link_bytes_sent(),
		.frames_captured = sn_radio154_captured(),
		.isr_queue_full = 0u,
		.link_rejected = sn_radio154_dropped(),
	};

	sn_link_send(SN_FRAME_STATS, (const uint8_t *)&stats, sizeof(stats));
	k_work_schedule(&stats_work, K_SECONDS(1));
}
#endif

int main(void)
{
	if (sn_link_init() != 0) {
		return -1;
	}

#if SN_MODE == SN_MODE_CONFORMANCE
	conformance_burst();
#elif SN_MODE == SN_MODE_CAPTURE
	if (sn_radio154_init() != 0) {
		return -1;
	}
	sn_link_set_command_handler(sn_control_handle);

	/* Travels as a LOG frame, not as bytes on the UART. If this ever
	 * appears as raw text in a capture, the backend is not installed and
	 * the data path is being corrupted. */
	LOG_INF("link up, mode=%d, firmware=%u", SN_MODE, SN_FIRMWARE_VERSION);

	/* The radio is NOT started here. For 802.15.4 the host sends no
	 * separate START -- SET_CHANNEL starts it, as capture.py's _configure
	 * says -- and starting at boot would capture on the default channel
	 * throughout the handshake and then attribute those frames to
	 * whichever channel was finally asked for. */
	k_work_schedule(&stats_work, K_SECONDS(1));

	while (true) {
		k_sleep(K_FOREVER);
	}
#endif
	return 0;
}
