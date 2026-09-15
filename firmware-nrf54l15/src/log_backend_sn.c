/* Zephyr log output, redirected into the frame protocol.
 *
 * There is one UART and the capture stream owns it, so a log line written
 * directly would arrive as unframed bytes in the middle of a packet. The C6
 * solves the same problem the same way in firmware/main/log_sink.c; only the
 * SDK's API differs.
 *
 * DEFERRED mode is not a detail here, it is the whole safety argument. In
 * IMMEDIATE mode a log message is formatted in the context that logged it,
 * which for this driver includes its RX thread -- and that thread's default
 * 800-byte stack was measured at 792 bytes used, eight from the edge. Pushing
 * it over does not fault or complain: reception simply stops, while every API
 * call still reports success. That cost a night to find, and it is written up
 * in docs/2026-09-14-nrf54l15-spike.md. Deferred formatting happens on the
 * logging thread instead, and CONFIG_IEEE802154_NRF5_RX_STACK_SIZE is raised
 * beside it for margin rather than relying on that alone.
 */

#include <zephyr/logging/log_backend.h>
#include <zephyr/logging/log_backend_std.h>
#include <zephyr/logging/log_core.h>
#include <zephyr/logging/log_output.h>

#include "frame.h"
#include "link.h"

/* One formatted line. Longer messages are truncated by log_output rather than
 * overrunning, which is the behaviour we want: a clipped log is a nuisance, a
 * corrupted capture stream is a defect. */
#define SN_LOG_BUF_SIZE 192

static uint8_t buf[SN_LOG_BUF_SIZE];

/* log_output hands us formatted bytes; each call becomes one LOG frame. The
 * host decodes these as UTF-8 and the conformance suite checks that, so
 * whatever arrives here must be text. */
static int out(uint8_t *data, size_t length, void *ctx)
{
	ARG_UNUSED(ctx);

	sn_link_send(SN_FRAME_LOG, data, length);
	return (int)length;
}

LOG_OUTPUT_DEFINE(sn_log_output, out, buf, sizeof(buf));

static void process(const struct log_backend *const backend,
		    union log_msg_generic *msg)
{
	ARG_UNUSED(backend);

	const log_format_func_t func = log_format_func_t_get(LOG_OUTPUT_TEXT);

	func(&sn_log_output, &msg->log, log_backend_std_get_flags());
}

static void init_backend(const struct log_backend *const backend)
{
	ARG_UNUSED(backend);
}

static void panic(struct log_backend const *const backend)
{
	ARG_UNUSED(backend);

	log_backend_std_panic(&sn_log_output);
}

static void dropped(const struct log_backend *const backend, uint32_t cnt)
{
	ARG_UNUSED(backend);

	/* Says so in-band rather than silently. A host that is told it lost
	 * log lines can say so; one that is not will believe it saw
	 * everything. */
	log_backend_std_dropped(&sn_log_output, cnt);
}

static int format_set(const struct log_backend *const backend, uint32_t log_type)
{
	ARG_UNUSED(backend);

	/* Text only. The host decodes LOG payloads as UTF-8. */
	return log_type == LOG_OUTPUT_TEXT ? 0 : -ENOTSUP;
}

static const struct log_backend_api api = {
	.process = process,
	.panic = panic,
	.init = init_backend,
	.dropped = IS_ENABLED(CONFIG_LOG_MODE_IMMEDIATE) ? NULL : dropped,
	.format_set = format_set,
};

LOG_BACKEND_DEFINE(sn_log_backend, api, true);
