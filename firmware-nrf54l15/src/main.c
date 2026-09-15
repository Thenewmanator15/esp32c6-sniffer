/* The XIAO nRF54L15 half of the sniffer.
 *
 * Speaks the same wire format as the ESP32-C6 firmware, by compiling the same
 * frame.c rather than reimplementing it. See firmware/shared/frame.h.
 */

#include <zephyr/kernel.h>

#include "frame.h"
#include "link.h"

/* Wire format this firmware speaks. Must match the nrf54l15 entry in
 * EXPECTED_FIRMWARE_VERSIONS in host/src/esp32c6_sniffer/capture.py; the host
 * refuses to open a capture until the two agree, because an older board packs
 * its metadata differently and every field would then decode to a confident
 * wrong number rather than an error. */
#define SN_FIRMWARE_VERSION 1u

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

	while (true) {
		sn_link_send(SN_FRAME_HEARTBEAT, NULL, 0);
		sn_link_send(SN_FRAME_PACKET, (const uint8_t *)hello, sizeof(hello) - 1);
		sn_link_send(SN_FRAME_PACKET, newline_bytes, sizeof(newline_bytes));
		sn_link_send(SN_FRAME_PACKET, all_bytes, sizeof(all_bytes));
		sn_link_send(SN_FRAME_PACKET, (const uint8_t *)wrap, sizeof(wrap) - 1);
		sn_link_send(SN_FRAME_LOG, (const uint8_t *)logmsg, sizeof(logmsg) - 1);
		k_sleep(K_MSEC(500));
	}
}
#endif

int main(void)
{
	if (sn_link_init() != 0) {
		return -1;
	}

#if SN_MODE == SN_MODE_CONFORMANCE
	conformance_burst();
#endif
	return 0;
}
