#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Redirects ESP_LOG output into SN_FRAME_LOG frames on the USB link.
 *
 * USB-C is the only cable, so a physical UART console cannot be read. Logs
 * therefore travel in-band as their own frame type and the host demultiplexes:
 * packets to Wireshark, log lines to a console.
 *
 * Call after sn_usb_link_init(). */
void sn_log_sink_install(void);

#ifdef __cplusplus
}
#endif
