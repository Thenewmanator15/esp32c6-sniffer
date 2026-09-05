#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Streams PACKET frames of `payload_len` bytes as fast as the link accepts
 * them, emitting a STATS frame once per second.
 *
 * Exists to measure sustained USB-Serial-JTAG throughput on the ESP32-C6, a
 * figure Espressif do not publish and which no third party appears to have
 * measured. The only comparable number available is ~770 kB/s on an ESP32-S3,
 * against a theoretical full-speed bulk ceiling of about 1.2 MB/s.
 *
 * Build with: idf.py build -DSN_MODE=1 -DSN_BENCH_PAYLOAD=<n> */
void sn_bench_start(size_t payload_len);

#ifdef __cplusplus
}
#endif
