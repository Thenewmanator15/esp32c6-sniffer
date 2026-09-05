idf_component_register(
    SRCS "main.c" "board.c"
    INCLUDE_DIRS "."
    REQUIRES esp_driver_gpio
)
