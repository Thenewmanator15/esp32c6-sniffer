#include "radio_ble.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "frame.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "usb_link.h"

#if CONFIG_BT_ENABLED
#include "esp_bt.h"

static const char *TAG = "radio_ble";

/* H4 packet types, the first byte of every packet over this transport. */
#define H4_COMMAND 0x01
#define H4_ACL     0x02
#define H4_EVENT   0x04

/* HCI opcodes, little-endian on the wire. OGF in the top six bits. */
#define OPCODE_RESET                 0x0C03
#define OPCODE_SET_EVENT_MASK        0x0C01
#define OPCODE_LE_SET_EVENT_MASK     0x2001
#define OPCODE_LE_SET_SCAN_PARAMS    0x200B
#define OPCODE_LE_SET_SCAN_ENABLE    0x200C
#define OPCODE_LE_SET_EXT_SCAN_PARAMS 0x2041
#define OPCODE_LE_SET_EXT_SCAN_ENABLE 0x2042
#define OPCODE_LE_PERIODIC_CREATE_SYNC    0x2044
#define OPCODE_LE_PERIODIC_CANCEL_SYNC    0x2045
#define OPCODE_LE_PERIODIC_TERMINATE_SYNC 0x2046

#define EVENT_COMMAND_COMPLETE 0x0E
#define EVENT_COMMAND_STATUS   0x0F
#define EVENT_LE_META          0x3E
#define LE_SUBEVENT_ADV_REPORT          0x02
#define LE_SUBEVENT_EXT_ADV_REPORT      0x0D
#define LE_SUBEVENT_SYNC_ESTABLISHED    0x0E
#define LE_SUBEVENT_PERIODIC_REPORT     0x0F
#define LE_SUBEVENT_SYNC_LOST           0x10

/* Concurrent periodic syncs. The controller supports a small number and each
 * costs radio time it would otherwise spend scanning, so this is deliberately
 * low rather than as many as it will take. */
#define MAX_PERIODIC_SYNCS 2

/* Scan interval and window are in units of 0.625 ms. */
#define SCAN_UNITS_PER_MS 8 / 5

#define RX_QUEUE_LEN 24

typedef struct {
    sn_ble_meta_t meta;
    uint16_t len;
    uint8_t data[SN_BLE_MAX_PACKET];
} rx_item_t;

typedef struct {
    uint8_t sid;
    uint8_t address_type;
    uint8_t address[6];
} sync_request_t;

static QueueHandle_t s_sync_queue;
static TaskHandle_t s_sync_task;
static bool s_periodic_enabled;
static uint8_t s_sync_count;

static QueueHandle_t s_rx_queue;
static TaskHandle_t s_rx_task;
static SemaphoreHandle_t s_cmd_done;
static SemaphoreHandle_t s_can_send;
static volatile uint16_t s_pending_opcode;
static volatile uint8_t s_pending_status;
static volatile bool s_running;
static bool s_controller_up;
static bool s_extended;          /* true once extended scanning is running */
static uint8_t s_phys = SN_BLE_PHY_1M;
static sn_ble_stats_t s_stats;

static uint8_t s_out[sizeof(sn_ble_meta_t) + SN_BLE_MAX_PACKET];

/* --- VHCI callbacks, both called from the controller task ---------------- */

static void vhci_send_available(void)
{
    if (s_can_send != NULL) {
        xSemaphoreGive(s_can_send);
    }
}

static int vhci_receive(uint8_t *data, uint16_t len)
{
    if (data == NULL || len == 0) {
        return 0;
    }
    s_stats.hci_packets++;

    /* Command Complete for whatever setup step is waiting. The layout is
     * type, event code, parameter length, num_hci_command_packets, opcode,
     * status -- so the opcode starts at offset 4 and the status follows it. */
    if (data[0] == H4_EVENT && len >= 7 && data[1] == EVENT_COMMAND_COMPLETE) {
        const uint16_t opcode = (uint16_t)(data[4] | (data[5] << 8));
        if (opcode == s_pending_opcode && s_cmd_done != NULL) {
            s_pending_status = data[6];
            xSemaphoreGive(s_cmd_done);
        }
    }
    /* Command Status, not Command Complete. Create Sync answers this way
     * because it starts something that finishes later, and waiting only for
     * Complete would have timed out on every attempt. Layout: status,
     * num_hci_command_packets, opcode. */
    if (data[0] == H4_EVENT && len >= 7 && data[1] == EVENT_COMMAND_STATUS) {
        const uint16_t opcode = (uint16_t)(data[5] | (data[6] << 8));
        if (opcode == s_pending_opcode && s_cmd_done != NULL) {
            s_pending_status = data[3];
            xSemaphoreGive(s_cmd_done);
        }
    }

    if (data[0] == H4_EVENT && len >= 4 && data[1] == EVENT_LE_META &&
        (data[3] == LE_SUBEVENT_ADV_REPORT ||
         data[3] == LE_SUBEVENT_EXT_ADV_REPORT)) {
        s_stats.adv_reports++;
    }

    /* An extended advertising report whose periodic interval is non-zero is
     * announcing a periodic advertising train. Syncing to it is the only way
     * to see the train's contents, and it is how LE Audio broadcasts are
     * found. The address and SID needed to sync are in this report and
     * nowhere else, so they are captured here.
     *
     * The request is queued rather than acted on: this runs in the
     * controller's own task, and issuing an HCI command from inside its
     * receive callback invites a deadlock. */
    if (s_periodic_enabled && data[0] == H4_EVENT && len >= 21 &&
        data[1] == EVENT_LE_META && data[3] == LE_SUBEVENT_EXT_ADV_REPORT &&
        data[4] == 1) {
        const uint8_t *report = data + 5;
        const uint16_t periodic_interval =
            (uint16_t)(report[14] | (report[15] << 8));
        if (periodic_interval != 0 && s_sync_queue != NULL) {
            sync_request_t request = {
                .sid = report[11],
                .address_type = report[2],
            };
            memcpy(request.address, report + 3, 6);
            s_stats.periodic_seen++;
            xQueueSend(s_sync_queue, &request, 0);
        }
    }

    if (data[0] == H4_EVENT && len >= 4 && data[1] == EVENT_LE_META) {
        if (data[3] == LE_SUBEVENT_PERIODIC_REPORT) {
            s_stats.periodic_reports++;
        } else if (data[3] == LE_SUBEVENT_SYNC_ESTABLISHED && len >= 6 &&
                   data[4] == 0x00) {
            s_stats.periodic_synced++;
        }
    }

    if (!s_running) {
        /* Setup traffic, not capture. Counted above, not forwarded: a capture
         * should contain what the radio heard, not our own configuration. */
        return 0;
    }

    rx_item_t item;
    uint16_t take = len;
    item.meta.flags = 0u;
    if (take > SN_BLE_MAX_PACKET) {
        take = SN_BLE_MAX_PACKET;
        item.meta.flags |= SN_BLE_FLAG_TRUNCATED;
        s_stats.oversized++;
    }
    /* esp_timer rather than a radio counter: the controller does not expose
     * one over HCI, so this is a host-side arrival time and is honest about
     * being that. */
    item.meta.timestamp_us = (uint64_t)esp_timer_get_time();
    item.meta.orig_len = len;
    item.meta.reserved = 0u;
    item.len = take;
    memcpy(item.data, data, take);

    if (xQueueSend(s_rx_queue, &item, 0) != pdTRUE) {
        s_stats.queue_full++;
    }
    return 0;
}

static const esp_vhci_host_callback_t s_vhci_callbacks = {
    .notify_host_send_available = vhci_send_available,
    .notify_host_recv = vhci_receive,
};

static void rx_task(void *arg)
{
    (void)arg;
    static rx_item_t item;

    while (true) {
        if (xQueueReceive(s_rx_queue, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        memcpy(s_out, &item.meta, sizeof(item.meta));
        memcpy(s_out + sizeof(item.meta), item.data, item.len);
        if (sn_usb_link_send(SN_FRAME_PACKET, s_out,
                             sizeof(item.meta) + item.len)) {
            s_stats.forwarded++;
        } else {
            s_stats.link_rejected++;
        }
    }
}

/* --- HCI command plumbing ------------------------------------------------ */

static esp_err_t send_command(uint16_t opcode, const uint8_t *params,
                              uint8_t param_len)
{
    uint8_t packet[4 + 255];
    packet[0] = H4_COMMAND;
    packet[1] = (uint8_t)(opcode & 0xFF);
    packet[2] = (uint8_t)(opcode >> 8);
    packet[3] = param_len;
    if (param_len > 0 && params != NULL) {
        memcpy(packet + 4, params, param_len);
    }

    /* The controller tells us when it can accept a packet. Sending regardless
     * is how a command gets silently dropped and the setup then waits for a
     * completion that will never come. */
    if (!esp_vhci_host_check_send_available()) {
        if (xSemaphoreTake(s_can_send, pdMS_TO_TICKS(1000)) != pdTRUE) {
            return ESP_ERR_TIMEOUT;
        }
    }

    xSemaphoreTake(s_cmd_done, 0);      /* drain a stale completion */
    s_pending_opcode = opcode;
    s_pending_status = 0xFF;
    esp_vhci_host_send_packet(packet, (uint16_t)(4 + param_len));

    if (xSemaphoreTake(s_cmd_done, pdMS_TO_TICKS(2000)) != pdTRUE) {
        s_pending_opcode = 0;
        s_stats.command_timeouts++;
        ESP_LOGE(TAG, "HCI opcode 0x%04x never completed", opcode);
        return ESP_ERR_TIMEOUT;
    }
    s_pending_opcode = 0;
    if (s_pending_status != 0x00) {
        ESP_LOGE(TAG, "HCI opcode 0x%04x refused, status 0x%02x", opcode,
                 s_pending_status);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* Extended scanning, which is what BLE 5 advertisements need.
 *
 * Legacy scanning reports only legacy advertisements: 31 bytes of payload on
 * the 1M PHY. Everything a BLE 5 device puts in an extended advertisement --
 * up to 1650 bytes, and anything sent on the Coded (long range) PHY -- is
 * simply not reported, and the capture looks quiet rather than incomplete.
 *
 * Extended scanning reports BOTH kinds, legacy ones arriving as extended
 * reports with a legacy flag, so nothing is lost by preferring it.
 *
 * The PHY bitmap only accepts 1M and Coded: primary advertising never uses the
 * 2M PHY, so a bit for it would be rejected. Each selected PHY gets its own
 * interval and window, and the controller time-shares between them -- adding
 * Coded therefore costs 1M coverage, which is why it is opt-in.
 */
static esp_err_t configure_extended_scan(uint16_t interval_ms,
                                         uint16_t window_ms)
{
    const uint16_t interval = (uint16_t)(interval_ms * SCAN_UNITS_PER_MS);
    const uint16_t window = (uint16_t)(window_ms * SCAN_UNITS_PER_MS);
    const uint8_t phys = (uint8_t)(s_phys & (SN_BLE_PHY_1M | SN_BLE_PHY_CODED));

    uint8_t params[3 + 2 * 5];
    uint8_t n = 0;
    params[n++] = 0x00;      /* own address type, public */
    params[n++] = 0x00;      /* accept everything */
    params[n++] = phys;
    for (uint8_t bit = 0; bit < 8; bit++) {
        if (!(phys & (1u << bit))) {
            continue;
        }
        params[n++] = 0x00;  /* passive: never transmit */
        params[n++] = (uint8_t)(interval & 0xFF);
        params[n++] = (uint8_t)(interval >> 8);
        params[n++] = (uint8_t)(window & 0xFF);
        params[n++] = (uint8_t)(window >> 8);
    }

    esp_err_t err = send_command(OPCODE_LE_SET_EXT_SCAN_PARAMS, params, n);
    if (err != ESP_OK) {
        return err;
    }
    /* enable, no duplicate filtering, no duration or period limit */
    const uint8_t enable[6] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    return send_command(OPCODE_LE_SET_EXT_SCAN_ENABLE, enable, sizeof(enable));
}

static esp_err_t configure_scan(uint16_t interval_ms, uint16_t window_ms)
{
    static const uint8_t all_events[8] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F};
    static const uint8_t all_le_events[8] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    esp_err_t err = send_command(OPCODE_RESET, NULL, 0);
    if (err != ESP_OK) {
        return err;
    }
    /* Without these two masks the controller answers every command happily and
     * never reports a single advertisement, because the events carrying them
     * are masked off by default. */
    err = send_command(OPCODE_SET_EVENT_MASK, all_events, sizeof(all_events));
    if (err != ESP_OK) {
        return err;
    }
    err = send_command(OPCODE_LE_SET_EVENT_MASK, all_le_events,
                       sizeof(all_le_events));
    if (err != ESP_OK) {
        return err;
    }

    /* Prefer extended unless legacy was asked for explicitly. Falling back
     * rather than failing means a controller without BLE 5 still captures
     * legacy advertisements, and the log says which happened rather than
     * leaving it to be guessed. */
    err = (s_phys == SN_BLE_PHY_LEGACY_ONLY)
              ? ESP_ERR_NOT_SUPPORTED
              : configure_extended_scan(interval_ms, window_ms);
    if (err == ESP_OK) {
        s_extended = true;
        ESP_LOGI(TAG, "extended scanning, PHYs 0x%02x", (unsigned)s_phys);
        return ESP_OK;
    }
    if (s_phys == SN_BLE_PHY_LEGACY_ONLY) {
        ESP_LOGI(TAG, "legacy scanning as requested; BLE 5 extended "
                      "advertisements will not be reported");
    } else {
        ESP_LOGW(TAG, "extended scanning unavailable (%s); falling back to "
                      "legacy, which cannot see BLE 5 extended advertisements",
                 esp_err_to_name(err));
    }
    s_extended = false;

    const uint16_t interval = (uint16_t)(interval_ms * SCAN_UNITS_PER_MS);
    const uint16_t window = (uint16_t)(window_ms * SCAN_UNITS_PER_MS);
    const uint8_t params[7] = {
        0x00,                          /* passive: never transmit */
        (uint8_t)(interval & 0xFF), (uint8_t)(interval >> 8),
        (uint8_t)(window & 0xFF), (uint8_t)(window >> 8),
        0x00,                          /* own address type, public */
        0x00,                          /* accept everything */
    };
    err = send_command(OPCODE_LE_SET_SCAN_PARAMS, params, sizeof(params));
    if (err != ESP_OK) {
        return err;
    }

    /* enable, and do NOT filter duplicates: a sniffer wants every repetition,
     * because the repetition rate is itself information. */
    const uint8_t enable[2] = {0x01, 0x00};
    return send_command(OPCODE_LE_SET_SCAN_ENABLE, enable, sizeof(enable));
}

esp_err_t sn_radio_ble_start(uint16_t interval_ms, uint16_t window_ms)
{
    if (s_running) {
        return ESP_OK;
    }
    if (interval_ms == 0) {
        interval_ms = SN_BLE_DEFAULT_INTERVAL_MS;
    }
    if (window_ms == 0 || window_ms > interval_ms) {
        window_ms = interval_ms;
    }

    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(RX_QUEUE_LEN, sizeof(rx_item_t));
        if (s_rx_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_cmd_done == NULL) {
        s_cmd_done = xSemaphoreCreateBinary();
        s_can_send = xSemaphoreCreateBinary();
        if (s_cmd_done == NULL || s_can_send == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_rx_task == NULL) {
        /* Below the USB sender, as the other radios are, so draining the link
         * always wins. */
        if (xTaskCreate(rx_task, "sn_ble", 4096, NULL, 9, &s_rx_task)
                != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    if (!s_controller_up) {
        esp_bt_controller_config_t cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        esp_err_t err = esp_bt_controller_init(&cfg);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "controller init: %s", esp_err_to_name(err));
            return err;
        }
        err = esp_bt_controller_enable(ESP_BT_MODE_BLE);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "controller enable: %s", esp_err_to_name(err));
            esp_bt_controller_deinit();
            return err;
        }
        err = esp_vhci_host_register_callback(&s_vhci_callbacks);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "vhci register: %s", esp_err_to_name(err));
            return err;
        }
        s_controller_up = true;
    }

    esp_err_t err = configure_scan(interval_ms, window_ms);
    if (err != ESP_OK) {
        return err;
    }

    s_running = true;
    ESP_LOGI(TAG, "scanning passively, interval %u ms window %u ms",
             (unsigned)interval_ms, (unsigned)window_ms);
    return ESP_OK;
}

void sn_radio_ble_stop(void)
{
    if (!s_controller_up) {
        return;
    }
    if (s_running) {
        if (s_extended) {
            const uint8_t disable[6] = {0, 0, 0, 0, 0, 0};
            send_command(OPCODE_LE_SET_EXT_SCAN_ENABLE, disable,
                         sizeof(disable));
        } else {
            const uint8_t disable[2] = {0x00, 0x00};
            send_command(OPCODE_LE_SET_SCAN_ENABLE, disable, sizeof(disable));
        }
        s_running = false;
    }

    /* Deinitialising the controller drops any periodic syncs along with it,
     * so the count is reset rather than left to block future ones. */
    s_sync_count = 0;
    if (s_sync_queue != NULL) {
        xQueueReset(s_sync_queue);
    }

    /* Hand the front end back properly. Disabling the scan alone leaves the
     * controller owning the radio, and the 802.15.4 radio has already shown
     * what that costs: the Wi-Fi receiver stays deaf until the RF domain is
     * power-gated. */
    esp_bt_controller_disable();
    esp_bt_controller_deinit();
    s_controller_up = false;
    ESP_LOGI(TAG, "scan stopped, controller released");
}

bool sn_radio_ble_running(void)
{
    return s_running;
}

bool sn_radio_ble_extended(void)
{
    return s_extended;
}

/* Issues the sync requests the receive callback queued. A task of its own
 * because HCI commands cannot be sent from inside the controller's callback,
 * and because Create Sync blocks until the controller answers.
 *
 * Create Sync answers with Command Status rather than Command Complete, since
 * it starts something that finishes later; waiting only for Complete would
 * have timed out on every attempt. */
static void sync_task(void *arg)
{
    (void)arg;
    sync_request_t request;

    while (true) {
        if (xQueueReceive(s_sync_queue, &request, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (!s_periodic_enabled || s_sync_count >= MAX_PERIODIC_SYNCS) {
            continue;
        }
        /* options 0: use the address given rather than the advertiser list,
         * and report from the start. skip 0, timeout 10 s in 10 ms units. */
        uint8_t params[14] = {0};
        params[1] = request.sid;
        params[2] = request.address_type;
        memcpy(params + 3, request.address, 6);
        params[11] = 0xE8; params[12] = 0x03;

        esp_err_t err = send_command(OPCODE_LE_PERIODIC_CREATE_SYNC, params,
                                     sizeof(params));
        if (err == ESP_OK) {
            s_sync_count++;
            ESP_LOGI(TAG, "syncing to a periodic train, SID %u",
                     (unsigned)request.sid);
        } else {
            /* A refusal is ordinary: the controller rejects a duplicate sync
             * to an advertiser it already follows, and every repeat of that
             * advertisement queues another request. */
            ESP_LOGD(TAG, "periodic sync refused: %s", esp_err_to_name(err));
        }
    }
}

esp_err_t sn_radio_ble_set_periodic(bool enable)
{
    if (enable) {
        if (s_sync_queue == NULL) {
            s_sync_queue = xQueueCreate(4, sizeof(sync_request_t));
            if (s_sync_queue == NULL) {
                return ESP_ERR_NO_MEM;
            }
        }
        if (s_sync_task == NULL) {
            if (xTaskCreate(sync_task, "sn_ble_sync", 4096, NULL, 8,
                            &s_sync_task) != pdPASS) {
                return ESP_ERR_NO_MEM;
            }
        }
    }
    s_periodic_enabled = enable;
    ESP_LOGI(TAG, "periodic advertising sync %s",
             enable ? "enabled" : "disabled");
    return ESP_OK;
}

esp_err_t sn_radio_ble_set_phys(uint8_t phys)
{
    /* 2M is not a primary advertising PHY, so the controller rejects a bitmap
     * containing it and the whole scan setup fails. Refuse it here, where the
     * reason can be given. */
    /* Zero means legacy scanning on purpose, which is worth having: it is
     * what makes "how much does extended actually add here" a measurement
     * rather than a claim. */
    if (phys != SN_BLE_PHY_LEGACY_ONLY &&
        (phys & ~(SN_BLE_PHY_1M | SN_BLE_PHY_CODED)) != 0u) {
        return ESP_ERR_INVALID_ARG;
    }
    s_phys = phys;
    return ESP_OK;
}

void sn_radio_ble_get_stats(sn_ble_stats_t *out)
{
    *out = s_stats;
}

#else /* !CONFIG_BT_ENABLED */

/* Built without Bluetooth. The stubs keep main.c compiling and report failure
 * honestly rather than pretending a radio is present. */
esp_err_t sn_radio_ble_start(uint16_t interval_ms, uint16_t window_ms)
{
    (void)interval_ms; (void)window_ms;
    return ESP_ERR_NOT_SUPPORTED;
}
void sn_radio_ble_stop(void) {}
bool sn_radio_ble_running(void) { return false; }
bool sn_radio_ble_extended(void) { return false; }
esp_err_t sn_radio_ble_set_phys(uint8_t phys)
{
    (void)phys;
    return ESP_ERR_NOT_SUPPORTED;
}
esp_err_t sn_radio_ble_set_periodic(bool enable)
{
    (void)enable;
    return ESP_ERR_NOT_SUPPORTED;
}
void sn_radio_ble_get_stats(sn_ble_stats_t *out) { memset(out, 0, sizeof(*out)); }

#endif /* CONFIG_BT_ENABLED */
