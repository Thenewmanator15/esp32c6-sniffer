idf_component_register(
    SRCS "main.c" "board.c" "frame.c" "usb_link.c" "log_sink.c" "bench.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio esp_driver_usb_serial_jtag esp_ringbuf esp_timer
)
