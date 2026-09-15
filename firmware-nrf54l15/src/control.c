/* Control channel, host to board.
 *
 * The host's side is esp32c6_sniffer.control. Commands arrive framed exactly
 * as everything else does, so the same parser handles both directions.
 *
 * Payload layouts, from that module's docstring:
 *   command  5 bytes  "<BI"   command id, then a little-endian 32-bit value
 *   reply    6 bytes  "<BBI"  echoed command id, status, then a value
 *
 * The command id is echoed rather than correlated by sequence number, because
 * the board assigns sequence numbers and the host cannot know them in advance.
 *
 * Only the commands this board can honour are implemented. Every other id gets
 * SN_STATUS_UNKNOWN_COMMAND rather than silence: the host tolerates a reply it
 * does not recognise, but a missing one stalls it until a timeout.
 */

#include "control.h"

#include <zephyr/logging/log.h>

#include <stddef.h>
#include <stdint.h>

#include "commands.h"
#include "frame.h"
#include "link.h"
#include "radio154.h"

LOG_MODULE_REGISTER(control, LOG_LEVEL_INF);

#define SN_CMD_PAYLOAD_LEN   5
#define SN_REPLY_PAYLOAD_LEN 6

static void reply(uint8_t command, uint8_t status, uint32_t value)
{
	uint8_t out[SN_REPLY_PAYLOAD_LEN];

	out[0] = command;
	out[1] = status;
	out[2] = (uint8_t)(value & 0xFFu);
	out[3] = (uint8_t)((value >> 8) & 0xFFu);
	out[4] = (uint8_t)((value >> 16) & 0xFFu);
	out[5] = (uint8_t)((value >> 24) & 0xFFu);

	sn_link_send(SN_FRAME_CONTROL_REPLY, out, sizeof(out));
}

void sn_control_handle(const uint8_t *payload, size_t len)
{
	if (len < SN_CMD_PAYLOAD_LEN) {
		return;
	}
	const uint8_t command = payload[0];
	const uint32_t value = (uint32_t)payload[1] |
			       ((uint32_t)payload[2] << 8) |
			       ((uint32_t)payload[3] << 16) |
			       ((uint32_t)payload[4] << 24);

	switch (command) {
	case SN_CMD_SET_RADIO:
		/* The host selects a radio before anything else, because
		 * SET_CHANNEL is interpreted against whichever is selected.
		 * This board has one: 802.15.4 is Radio.IEEE802154 == 0 in
		 * esp32c6_sniffer.control. Wi-Fi does not exist on this part
		 * at all and BLE has no firmware behind it, so both are
		 * refused rather than quietly accepted. */
		reply(command,
		      value == 0u ? SN_STATUS_OK : SN_STATUS_BAD_VALUE,
		      value);
		break;

	case SN_CMD_SET_CHANNEL:
		/* SET_CHANNEL starts the radio, which is what the host
		 * expects: for 802.15.4 it sends no separate START, and the
		 * comment in capture.py's _configure says so explicitly.
		 * Starting here rather than at boot also means nothing is
		 * captured on the default channel during the handshake and
		 * then attributed to the channel that was asked for. */
		if (sn_radio154_set_channel((uint8_t)value) != 0) {
			reply(command, SN_STATUS_BAD_VALUE, value);
			break;
		}
		/* Worth saying out loud. The operator picked a channel and the
		 * capture is about to be attributed to it, so a mismatch
		 * between what was asked for and what the radio took is the
		 * kind of thing that should be visible rather than inferred. */
		if (sn_radio154_start() != 0) {
			LOG_ERR("channel %u set but the radio would not start",
				(unsigned)value);
			reply(command, SN_STATUS_FAILED, value);
			break;
		}
		LOG_INF("channel %u, receiving", (unsigned)value);
		reply(command, SN_STATUS_OK, value);
		break;

	case SN_CMD_START:
		reply(command,
		      sn_radio154_start() == 0 ? SN_STATUS_OK : SN_STATUS_FAILED,
		      0u);
		break;

	case SN_CMD_STOP:
		reply(command,
		      sn_radio154_stop() == 0 ? SN_STATUS_OK : SN_STATUS_FAILED,
		      0u);
		break;

	case SN_CMD_GET_INFO:
		/* The host refuses to open a capture until this matches
		 * EXPECTED_FIRMWARE_VERSIONS["nrf54l15"], because an older
		 * board packs its metadata differently and every field would
		 * then decode to a confident wrong number rather than an
		 * error. */
		reply(command, SN_STATUS_OK, sn_firmware_version());
		break;

	case SN_CMD_SET_ANTENNA:
		/* This board does have an RF switch, but which position
		 * selects which antenna is not established -- see
		 * docs/2026-09-14-nrf54l15-spike.md.
		 *
		 * Antenna.INTERNAL == 0 is "leave it as the board brought it
		 * up", which is exactly what happens here, so it is honest to
		 * accept it. Asking for the external antenna is refused rather
		 * than accepted and ignored: a control that silently does
		 * nothing is worse than one that says it cannot. */
		reply(command,
		      value == 0u ? SN_STATUS_OK : SN_STATUS_BAD_VALUE,
		      value);
		break;

	default:
		reply(command, SN_STATUS_UNKNOWN_COMMAND, 0u);
		break;
	}
}
