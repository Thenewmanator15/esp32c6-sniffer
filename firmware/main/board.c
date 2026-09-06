#include "board.h"

#include <stdbool.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "board";

/* How long the RF switch's power rail needs before the part is usable.
 * Named rather than buried so the one place it is paid is obvious. */
#define SN_RF_SWITCH_SETTLE_MS 100

/* Survives across calls, not across a reset: after a reset the rail is
 * down and GPIO3 is pulled UP, which leaves the switch unpowered. That
 * is the fault that made stock examples look deaf, so the first call
 * after boot must always settle. */
static bool s_switch_powered;

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

    /* Settle only on the way up. The delay is for the switch's power rail,
     * which is why it sits between powering the part and choosing an antenna
     * rather than after the choice -- and a rail that is already up does not
     * need settling again.
     *
     * It was unconditional, so every SET_ANTENNA cost 100 ms whatever it was
     * asked for. Measured on the board's own trace: 100.1, 99.7, 100.1, 100.2,
     * 99.4, 99.9 ms for six calls, three of which changed nothing. A capture
     * pays one at start-up, and the toolbar's antenna A/B pays one per click. */
    if (!s_switch_powered) {
        vTaskDelay(pdMS_TO_TICKS(SN_RF_SWITCH_SETTLE_MS));
        s_switch_powered = true;
    }

    err = gpio_set_level(SN_PIN_ANTENNA_SEL,
                         antenna == SN_ANTENNA_EXTERNAL ? 1 : 0);
    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGI(TAG, "RF switch powered, antenna=%s",
             antenna == SN_ANTENNA_EXTERNAL ? "external" : "internal");
    return ESP_OK;
}
