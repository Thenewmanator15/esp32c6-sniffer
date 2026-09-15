/* IEEE 802.15.4 capture on the nRF54L15.
 *
 * Zephyr's raw 802.15.4 mode delivers every received frame to net_recv_data(),
 * which in RAW mode the application provides -- there is no network stack
 * above it. The API used here is transcribed from the NCS v3.4.0 sample rather
 * than remembered: net_recv_data returns int, not enum net_verdict, and the
 * PSDU comes from the buffer chain rather than from pkt->frags.
 *
 * Reception on this part is not supported by Nordic and was hard-won. Before
 * changing anything here, read docs/2026-09-14-nrf54l15-spike.md: two binaries
 * with byte-identical Kconfig differ deterministically, so if frames stop
 * arriving after an unrelated edit, that is the first thing to suspect.
 */

#include "radio154.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/net/ieee802154_radio.h>
#include <zephyr/net/net_pkt.h>

#include <nrf_802154.h>

#include "frame.h"
#include "link.h"

static const struct device *const radio =
	DEVICE_DT_GET(DT_CHOSEN(zephyr_ieee802154));
static struct ieee802154_radio_api *api;

static uint8_t current_channel = 11;
static uint32_t captured;
static uint32_t dropped;

/* The largest PSDU an 802.15.4 frame can carry. */
#define SN_154_MAX_PSDU 127

int sn_radio154_init(void)
{
	if (!device_is_ready(radio)) {
		return -ENODEV;
	}
	api = (struct ieee802154_radio_api *)radio->api;
	if (api == NULL) {
		return -ENODEV;
	}

	/* Acknowledgements OFF, and this is not optional. The driver
	 * auto-acknowledges by default, which would make this board transmit.
	 * A sniffer that ACKs is not passive, and passivity is a claim this
	 * project makes. Nordic's own sample does this for the same reason. */
#if !IS_ENABLED(CONFIG_NRF_802154_SERIALIZATION)
	nrf_802154_auto_ack_set(false);
#endif

	/* Promiscuous, or the driver filters to frames addressed to us and a
	 * sniffer sees almost nothing. */
	struct ieee802154_config config = { .promiscuous = true };
	return api->configure(radio, IEEE802154_CONFIG_PROMISCUOUS, &config);
}

int sn_radio154_set_channel(uint8_t channel)
{
	/* Checked on the host too, but a board that trusts the wire is one
	 * corrupted byte away from tuning somewhere meaningless. */
	if (channel < 11u || channel > 26u) {
		return -EINVAL;
	}
	const int err = api->set_channel(radio, channel);
	if (err == 0) {
		current_channel = channel;
	}
	return err;
}

int sn_radio154_start(void)
{
	return api->start(radio);
}

int sn_radio154_stop(void)
{
	return api->stop(radio);
}

uint8_t sn_radio154_channel(void)
{
	return current_channel;
}

uint32_t sn_radio154_captured(void)
{
	return captured;
}

uint32_t sn_radio154_dropped(void)
{
	return dropped;
}

/* Every received frame arrives here. */
int net_recv_data(struct net_if *iface, struct net_pkt *pkt)
{
	ARG_UNUSED(iface);

	if (pkt == NULL) {
		return -EINVAL;
	}
	if (net_pkt_is_empty(pkt)) {
		net_pkt_unref(pkt);
		return -ENODATA;
	}

	const uint8_t *psdu = net_buf_frag_last(pkt->buffer)->data;
	size_t length = net_buf_frags_len(pkt->buffer);

	/* A net_ptp_time, seconds plus nanoseconds. There is no
	 * net_pkt_timestamp_ns() on this path. */
	struct net_ptp_time *pkt_time = net_pkt_timestamp(pkt);

	struct sn_154_meta meta = {
		.channel = current_channel,
		.lqi = net_pkt_ieee802154_lqi(pkt),
		.rssi_dbm = (int8_t)net_pkt_ieee802154_rssi_dbm(pkt),
		/* SN_154_FLAG_HAS_FCS stays clear: the driver strips the
		 * checksum before we see the frame, exactly as the C6's does,
		 * so claiming an FCS is present would be a lie the host would
		 * believe. */
		.flags = 0u,
		.timestamp_us = (uint64_t)pkt_time->second * 1000000ULL +
				(uint64_t)pkt_time->nanosecond / 1000ULL,
	};

	static uint8_t payload[sizeof(struct sn_154_meta) + SN_154_MAX_PSDU];

	if (length > SN_154_MAX_PSDU) {
		length = SN_154_MAX_PSDU;
	}
	memcpy(payload, &meta, sizeof(meta));
	memcpy(payload + sizeof(meta), psdu, length);

	captured++;
	if (sn_link_send(SN_FRAME_PACKET, payload, sizeof(meta) + length) != 0) {
		dropped++;
	}

	net_pkt_unref(pkt);
	return 0;
}

/* Acknowledgements are not traffic worth reporting, and in promiscuous mode
 * the stack asks what to do with them. */
enum net_verdict ieee802154_handle_ack(struct net_if *iface, struct net_pkt *pkt)
{
	ARG_UNUSED(iface);
	ARG_UNUSED(pkt);

	return NET_DROP;
}
