idf_component_register(
    SRCS "main.c" "board.c" "frame.c" "usb_link.c" "log_sink.c"
         "bench.c" "control.c" "radio154.c" "radio80211.c" "radio_ble.c"
           "trace.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio esp_driver_usb_serial_jtag esp_ringbuf esp_timer ieee802154
             esp_wifi nvs_flash esp_event esp_netif bt
)

# Build-time mode selection, e.g.
#   idf.py -DSN_MODE=1 -DSN_BENCH_PAYLOAD=256 build
# SN_MODE 0 = conformance burst (default, used by the host test suite)
# SN_MODE 1 = throughput benchmark
if(DEFINED SN_MODE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE SN_MODE=${SN_MODE})
endif()
if(DEFINED SN_BENCH_PAYLOAD)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
                               SN_BENCH_PAYLOAD=${SN_BENCH_PAYLOAD})
endif()

# Transport tuning, for throughput experiments.
if(DEFINED SN_TX_CHUNK)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
                               SN_TX_CHUNK=${SN_TX_CHUNK})
endif()
if(DEFINED SN_TX_BUFFER)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
                               SN_TX_BUFFER=${SN_TX_BUFFER})
endif()
