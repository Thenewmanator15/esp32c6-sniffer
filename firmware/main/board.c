#include "board.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "board";

esp_err_t sn_board_init(sn_antenna_t antenna)
{
    const gpio_config_t io = {
        .pin_bit_mask = (1ULL << SN_PIN_RF_SWITCH_PWR) |
                        (1ULL << SN_PIN_ANTENNA_SEL),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&io);
    if (err != ESP_OK) {
        return err;
    }

    /* Power the RF switch. LOW = on. Always, for either antenna. */
    err = gpio_set_level(SN_PIN_RF_SWITCH_PWR, 0);
    if (err != ESP_OK) {
        return err;
    }
    vTaskDelay(pdMS_TO_TICKS(100));

    err = gpio_set_level(SN_PIN_ANTENNA_SEL,
                         antenna == SN_ANTENNA_EXTERNAL ? 1 : 0);
    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGI(TAG, "RF switch powered, antenna=%s",
             antenna == SN_ANTENNA_EXTERNAL ? "external" : "internal");
    return ESP_OK;
}
