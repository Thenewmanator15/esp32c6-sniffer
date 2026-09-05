#include "board.h"

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "main";

void app_main(void)
{
    ESP_ERROR_CHECK(sn_board_init(SN_ANTENNA_INTERNAL));
    ESP_LOGI(TAG, "milestone 1 scaffold up");

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
