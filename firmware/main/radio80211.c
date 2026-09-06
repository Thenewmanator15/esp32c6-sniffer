#include "radio80211.h"

#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "frame.h"
#include "trace.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "usb_link.h"

static const char *TAG = "radio80211";

/* Espressif's own guidance for this callback is blunt: it runs in the Wi-Fi
 * driver task, and if the application does much work per frame it should post
 * elsewhere and defer. They also warn that promiscuous mode "has a great impact
 * on throughput". So the callback copies and queues, nothing more. */
#define RX_QUEUE_LEN   24
#define MAX_SNAPLEN    SN_80211_MAX_SNAPLEN
#define DEFAULT_SNAPLEN 256

typedef struct {
    sn_80211_meta_t meta;
    uint16_t len;
    uint8_t data[MAX_SNAPLEN];
} rx_item_t;

static QueueHandle_t s_rx_queue;
static TaskHandle_t s_rx_task;
static uint8_t s_channel;
static uint16_t s_snaplen = DEFAULT_SNAPLEN;
static volatile bool s_running;
static sn_80211_stats_t s_stats;
static bool s_wifi_inited;
static uint32_t s_filter_mask = SN_80211_FILTER_ALL;
/* Snapshot of the callback count at the last service() tick, to spot a
 * receiver that has stopped delivering without reporting anything. */
static uint32_t s_last_seen_callbacks;
/* Grows each time a rebuild fails to bring the receiver back, so a fault the
 * driver cannot fix is not met by tearing the stack down every 15 seconds
 * forever. Reset as soon as a frame arrives. */
static uint32_t s_stall_limit = SN_80211_STALL_LIMIT_S;
/* Wrap tracking for the radio's 32-bit microsecond counter. Touched only by
 * the receive callback, which is serialised by the driver task. */
static uint32_t s_ts_last;
static uint64_t s_ts_epoch;
static uint8_t s_bandwidth = SN_80211_BW_20;
static uint32_t s_ctrl_filter;      /* 0 = leave the driver's default alone */
static bool s_csi_enabled;

/* Sender-owned; only the rx task touches it. */
static uint8_t s_out[sizeof(sn_80211_meta_t) + MAX_SNAPLEN];

static void promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    s_stats.callbacks++;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    if (pkt == NULL) {
        return;
    }

    /* MISC frames carry no usable payload. */
    if (type == WIFI_PKT_MISC) {
        s_stats.skipped_misc++;
        return;
    }

    /* The FCS is on the end of every frame and must come off.
     *
     * Measured on this chip rather than taken from the header, whose comments
     * point the wrong way: dump_len reads FOUR BYTES LARGER than sig_len, not
     * smaller, so it is not "the MPDU excluding the FCS" as documented. What
     * sig_len does include is the four-byte FCS, confirmed by walking the
     * information-element chain of a captured probe request: the tags end
     * exactly four bytes before sig_len, and those four parse as a bogus
     * empty SSID followed by a tag that overruns the frame.
     *
     * This hid for a long time because a frame longer than the snapshot length
     * is marked truncated, and Wireshark stops parsing before reaching the
     * tail. Only short complete frames showed it -- which is why every probe
     * request was malformed while beacons looked fine. */
    const uint16_t with_fcs = (uint16_t)pkt->rx_ctrl.sig_len;
    uint16_t on_air = 0;
    if (with_fcs > SN_80211_FCS_LEN) {
        on_air = (uint16_t)(with_fcs - SN_80211_FCS_LEN);
    } else {
        /* Too short to hold an FCS at all: not a frame we can make sense of. */
        s_stats.fcs_length_unknown++;
    }
    if (on_air == 0) {
        s_stats.skipped_zero_len++;
        return;
    }

    rx_item_t item;
    item.meta.channel = (uint8_t)pkt->rx_ctrl.channel;
    item.meta.rssi_dbm = (int8_t)pkt->rx_ctrl.rssi;
    item.meta.noise_floor = (int8_t)pkt->rx_ctrl.noise_floor;
    /* Widen the 32-bit counter. A backwards step of more than half the range
     * is a wrap; a smaller one is the counter being reset, which happens when
     * the driver is torn down and rebuilt after a stall, and must NOT be
     * counted as 71 minutes of elapsed time. */
    const uint32_t raw_ts = (uint32_t)pkt->rx_ctrl.timestamp;
    if (raw_ts < s_ts_last && (s_ts_last - raw_ts) > 0x80000000u) {
        s_ts_epoch += 0x100000000ull;
    }
    s_ts_last = raw_ts;
    item.meta.timestamp_us = s_ts_epoch + raw_ts;
    item.meta.orig_len = on_air;
    /* cur_bb_format distinguishes 11b from everything else, so the host can
     * label CCK as CCK. Assuming OFDM for every frame was wrong for 11b, which
     * is exactly what beacons from older access points use. */
    item.meta.rate = (uint8_t)pkt->rx_ctrl.rate;
    item.meta.phy = (uint8_t)((pkt->rx_ctrl.cur_bb_format & 0x0Fu) |
                              ((pkt->rx_ctrl.second & 0x0Fu) << 4));
    /* Forwarded raw; the host decodes it. */
    item.meta.siga1 = (uint32_t)pkt->rx_ctrl.he_siga1;
    item.meta.siga2 = (uint16_t)pkt->rx_ctrl.he_siga2;
    item.meta.flags = (pkt->rx_ctrl.rx_state != 0) ? SN_80211_FLAG_RX_ERROR : 0u;
    /* cur_single_mpdu is set for a lone MPDU, so its absence means aggregate.
     * One A-MPDU is one transmission opportunity however many frames it
     * carries, which is the difference between a channel being busy and being
     * merely talkative.
     *
     * Only meaningful from HT onwards: 11b and 11g have no aggregation, and
     * the field simply reads 0 for them. Trusting it there marked every CCK
     * probe request as aggregated, and Wireshark then tried to reassemble
     * them -- 167 malformed frames in one 25 s capture, all probe requests. */
    if (pkt->rx_ctrl.cur_bb_format >= 2 /* RX_BB_FORMAT_HT */ &&
        !pkt->rx_ctrl.cur_single_mpdu) {
        item.meta.flags |= SN_80211_FLAG_AMPDU;
    }

    uint16_t take = on_air;
    if (take > s_snaplen) {
        take = s_snaplen;
        item.meta.flags |= SN_80211_FLAG_TRUNCATED;
    }
    if (take > MAX_SNAPLEN) {
        take = MAX_SNAPLEN;
    }
    item.len = take;

    /* Copy now. Unlike the 802.15.4 driver, which hands over a buffer we own
     * until we release it, this buffer's lifetime is undocumented and the
     * driver is closed source. Retaining the pointer would be a guess. */
    memcpy(item.data, pkt->payload, take);

    if (xQueueSend(s_rx_queue, &item, 0) != pdTRUE) {
        s_stats.isr_queue_full++;
        return;
    }
    if (take < on_air) {
        s_stats.frames_truncated++;
        s_stats.bytes_dropped_by_snaplen += (uint32_t)(on_air - take);
    }
}

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
            s_stats.frames_captured++;
        } else {
            s_stats.link_rejected++;
        }
    }
}

/* Brings the Wi-Fi driver up, once. Mode and start are deliberately NOT done
 * here: promiscuous capture wants NULL mode and scanning wants STA, so each
 * caller sets its own and then starts.
 *
 * This lived inside sn_radio80211_start() and nothing else could reach it,
 * so sn_radio80211_scan() -- which never calls start() -- ran against an
 * uninitialised driver and returned ESP_ERR_WIFI_NOT_INIT from its very first
 * call. The scan reported zero access points, and zero was read as "the radio
 * heard nothing" rather than "the radio was never switched on". That mistake
 * cost a long detour into imagined hardware faults. */
static esp_err_t wifi_init_once_inner(void)
{
    if (s_wifi_inited) {
        return ESP_OK;
    }

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        return err;
    }

    /* The driver posts events during start-up and needs somewhere to post
     * them. Without this it logs "failed to post WiFi event ... ret=259"
     * (invalid state) and never delivers frames. Already-created is fine,
     * since another component may have made one. */
    err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }
    /* The example reaches this via initialize_eth(); we have no Ethernet, so
     * call it directly. */
    err = esp_netif_init();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        return err;
    }

    /* WIFI_INIT_CONFIG_DEFAULT rather than a hand-rolled initialiser: v6 added
     * two fields to wifi_init_config_t, and anything filling the struct by hand
     * breaks silently. */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        return err;
    }
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    s_wifi_inited = true;
    return ESP_OK;
}

static esp_err_t wifi_init_once(void)
{
    /* Untraced once it is done: after the first call this is a flag test, and
     * an event per call would bury the one that matters. */
    if (s_wifi_inited) {
        return ESP_OK;
    }
    sn_trace(SN_TRACE_WIFI_INIT_IN, 0, 0);
    const esp_err_t err = wifi_init_once_inner();
    sn_trace(SN_TRACE_WIFI_INIT_OUT, 0, (uint16_t)err);
    return err;
}

/* An explicit union rather than all-ones. ALL is documented as 0xFFFFFFFF, but
 * naming the types we want removes any doubt about reserved bits being
 * interpreted. */
static wifi_second_chan_t second_chan(void)
{
    switch (s_bandwidth) {
    case SN_80211_BW_40_ABOVE: return WIFI_SECOND_CHAN_ABOVE;
    case SN_80211_BW_40_BELOW: return WIFI_SECOND_CHAN_BELOW;
    default:                   return WIFI_SECOND_CHAN_NONE;
    }
}

/* --- Channel state information ------------------------------------------
 *
 * CSI is the per-subcarrier channel response: what RSSI is a one-number
 * summary of. The driver hands it over in its own callback, in a buffer that
 * is freed as soon as the callback returns, so it must be copied.
 *
 * It goes to the host as its own frame type. No pcap link type has anywhere to
 * put it, and inventing a place inside radiotap would make captures that only
 * this project can read.
 */

typedef struct {
    uint8_t out[SN_80211_CSI_HEADER + SN_80211_CSI_MAX];
    uint16_t len;               /* total, header included */
} csi_item_t;

static QueueHandle_t s_csi_queue;
static TaskHandle_t s_csi_task;

static void csi_task(void *arg)
{
    (void)arg;
    static csi_item_t item;

    while (true) {
        if (xQueueReceive(s_csi_queue, &item, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (sn_usb_link_send(SN_FRAME_CSI, item.out, item.len)) {
            s_stats.csi_records++;
        } else {
            s_stats.csi_dropped++;
        }
    }
}

/* Runs in the Wi-Fi driver task. Copies and queues, nothing else. */
static void csi_cb(void *ctx, wifi_csi_info_t *info)
{
    (void)ctx;
    if (info == NULL || info->buf == NULL || info->len == 0) {
        return;
    }
    if (info->len > SN_80211_CSI_MAX) {
        /* Better to count it than to send a silently half-truncated channel
         * response, which would look like real data. */
        s_stats.csi_dropped++;
        return;
    }

    csi_item_t item;
    uint8_t *p = item.out;
    const uint32_t raw_ts = (uint32_t)info->rx_ctrl.timestamp;
    const uint64_t ts = s_ts_epoch + raw_ts;
    memcpy(p, &ts, 8);                                   p += 8;
    *p++ = (uint8_t)(int8_t)info->rx_ctrl.rssi;
    *p++ = (uint8_t)(int8_t)info->rx_ctrl.noise_floor;
    *p++ = (uint8_t)info->rx_ctrl.channel;
    *p++ = (uint8_t)((info->rx_ctrl.cur_bb_format & 0x0Fu) |
                     ((info->rx_ctrl.second & 0x0Fu) << 4));
    memcpy(p, info->mac, 6);                             p += 6;
    const uint16_t seq = info->rx_seq;
    memcpy(p, &seq, 2);                                  p += 2;
    *p++ = info->first_word_invalid
               ? SN_80211_CSI_FLAG_FIRST_WORD_INVALID : 0u;
    const uint16_t csi_len = info->len;
    memcpy(p, &csi_len, 2);                              p += 2;
    memcpy(p, info->buf, csi_len);

    item.len = (uint16_t)(SN_80211_CSI_HEADER + csi_len);

    if (xQueueSend(s_csi_queue, &item, 0) != pdTRUE) {
        s_stats.csi_dropped++;
    }
}

esp_err_t sn_radio80211_set_csi(bool enable)
{
    if (!enable) {
        s_csi_enabled = false;
        return s_wifi_inited ? esp_wifi_set_csi(false) : ESP_OK;
    }

    if (s_csi_queue == NULL) {
        /* Shallow: each entry is over half a kilobyte, and CSI is a diagnostic
         * stream rather than the capture. Dropping one is visible in the
         * counters and costs nothing that matters. */
        s_csi_queue = xQueueCreate(4, sizeof(csi_item_t));
        if (s_csi_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_csi_task == NULL) {
        if (xTaskCreate(csi_task, "sn_csi", 4096, NULL, 8, &s_csi_task)
                != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    s_csi_enabled = true;
    if (!s_wifi_inited) {
        return ESP_OK; /* remembered, applied when the radio starts */
    }

    /* Legacy and HT20 long training fields. HT40 and the HE variants are left
     * off: they multiply the record size, and this link is the constraint. */
    wifi_csi_config_t cfg = {
        .enable = 1,
        .acquire_csi_legacy = 1,
        .acquire_csi_ht20 = 1,
        .acquire_csi_su = 1,
        .val_scale_cfg = 0,
        /* Acknowledgements are short, numerous and carry no payload worth
         * correlating a channel response against. */
        .dump_ack_en = 0,
    };
    /* No lltf_bit_mode here: that field exists only on MAC version 3 parts,
     * and the C6 is not one. Records are 12-bit I/Q as a result. */
    /* Each step logged with its own error code: a bare ESP_FAIL from this
     * function said nothing about which of the three calls refused, which is
     * exactly the trap the scan path already fell into once. */
    esp_err_t err = esp_wifi_set_csi_config(&cfg);
    ESP_LOGI(TAG, "csi: set_csi_config -> %s", esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }
    err = esp_wifi_set_csi_rx_cb(csi_cb, NULL);
    ESP_LOGI(TAG, "csi: set_csi_rx_cb -> %s", esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }
    err = esp_wifi_set_csi(true);
    ESP_LOGI(TAG, "csi: set_csi(true) -> %s", esp_err_to_name(err));
    return err;
}

esp_err_t sn_radio80211_set_bandwidth(uint8_t bandwidth)
{
    if (bandwidth > SN_80211_BW_40_BELOW) {
        return ESP_ERR_INVALID_ARG;
    }
    s_bandwidth = bandwidth;
    if (!s_running) {
        return ESP_OK; /* remembered, applied when capture starts */
    }
    /* Re-tune so the change takes effect now rather than at the next retune. */
    esp_err_t err = esp_wifi_set_channel(s_channel, second_chan());
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "bandwidth now %s",
                 bandwidth == SN_80211_BW_20 ? "20 MHz" :
                 bandwidth == SN_80211_BW_40_ABOVE ? "40 MHz, secondary above"
                                                   : "40 MHz, secondary below");
    }
    return err;
}

esp_err_t sn_radio80211_set_ctrl_filter(uint32_t mask)
{
    s_ctrl_filter = mask;
    if (!s_running) {
        return ESP_OK;
    }
    wifi_promiscuous_filter_t filter = {.filter_mask = mask};
    esp_err_t err = esp_wifi_set_promiscuous_ctrl_filter(&filter);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "control-frame subtypes now 0x%08x", (unsigned)mask);
    }
    return err;
}

static esp_err_t apply_filter(uint32_t filter_mask)
{
    if (filter_mask == SN_80211_FILTER_ALL) {
        filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                      WIFI_PROMIS_FILTER_MASK_DATA |
                      WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    wifi_promiscuous_filter_t filter = {.filter_mask = filter_mask};
    return esp_wifi_set_promiscuous_filter(&filter);
}

/* --- Associating, so an access point has an 11ax client to talk to ------- */

static volatile uint8_t s_connected_channel;
static SemaphoreHandle_t s_connected;
static SemaphoreHandle_t s_got_ip;
static esp_netif_t *s_sta_netif;
static TaskHandle_t s_traffic_task;
static volatile bool s_traffic_wanted;
static volatile uint32_t s_gateway;
static volatile uint32_t s_traffic_bytes;

static void wifi_event(void *arg, esp_event_base_t base, int32_t id,
                       void *data)
{
    (void)arg; (void)base;
    if (id == WIFI_EVENT_STA_CONNECTED) {
        const wifi_event_sta_connected_t *ev =
            (const wifi_event_sta_connected_t *)data;
        s_connected_channel = ev->channel;
        ESP_LOGI(TAG, "associated on channel %u", (unsigned)ev->channel);
        if (s_connected != NULL) {
            xSemaphoreGive(s_connected);
        }
    } else if (id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *ev = (const ip_event_got_ip_t *)data;
        s_gateway = ev->ip_info.gw.addr;
        ESP_LOGI(TAG, "address " IPSTR ", gateway " IPSTR,
                 IP2STR(&ev->ip_info.ip), IP2STR(&ev->ip_info.gw));
        if (s_got_ip != NULL) {
            xSemaphoreGive(s_got_ip);
        }
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        const wifi_event_sta_disconnected_t *ev =
            (const wifi_event_sta_disconnected_t *)data;
        /* The reason code is the useful part: a wrong passphrase and an
         * absent network look identical without it. */
        ESP_LOGW(TAG, "disconnected, reason %u", (unsigned)ev->reason);
        s_connected_channel = 0;
    }
}

uint8_t sn_radio80211_connected_channel(void)
{
    return s_connected_channel;
}

esp_err_t sn_radio80211_connect(const char *ssid, const char *passphrase)
{
    esp_err_t err = wifi_init_once();
    if (err != ESP_OK) {
        return err;
    }
    if (s_connected == NULL) {
        s_connected = xSemaphoreCreateBinary();
        if (s_connected == NULL) {
            return ESP_ERR_NO_MEM;
        }
        s_got_ip = xSemaphoreCreateBinary();
        esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                            wifi_event, NULL, NULL);
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                            wifi_event, NULL, NULL);
    }

    /* A network interface, so DHCP runs and the link carries actual traffic.
     * Without one the association completes and then nothing happens: an idle
     * link gives the access point nothing to send, and HE is only used for
     * data frames, so the capture stays legacy and the exercise proves
     * nothing. */
    if (s_sta_netif == NULL) {
        s_sta_netif = esp_netif_create_default_wifi_sta();
        if (s_sta_netif == NULL) {
            return ESP_FAIL;
        }
    }

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        return err;
    }

    wifi_config_t cfg = {0};
    strncpy((char *)cfg.sta.ssid, ssid, sizeof(cfg.sta.ssid) - 1);
    strncpy((char *)cfg.sta.password, passphrase,
            sizeof(cfg.sta.password) - 1);
    /* Scan every channel rather than trusting a stored one, and pick the
     * strongest match: the same network name is usually on 2.4 and 5 GHz, and
     * this radio can only use one of them. */
    cfg.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    cfg.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    if (err != ESP_OK) {
        return err;
    }

    esp_wifi_start();
    xSemaphoreTake(s_connected, 0);
    err = esp_wifi_connect();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "connect: %s", esp_err_to_name(err));
        return err;
    }
    if (xSemaphoreTake(s_connected, pdMS_TO_TICKS(15000)) != pdTRUE) {
        ESP_LOGE(TAG, "association timed out");
        return ESP_ERR_TIMEOUT;
    }
    /* Associated is not the same as usable: DHCP has to finish before there
     * is anywhere to send traffic. Not fatal if it does not -- the capture is
     * still running -- so this warns rather than failing. */
    if (xSemaphoreTake(s_got_ip, pdMS_TO_TICKS(15000)) != pdTRUE) {
        ESP_LOGW(TAG, "no address from DHCP; the link will stay idle");
    }

    /* Capture on whatever channel the association landed on; anything else
     * would be watching a channel this radio is not on. */
    if (s_running) {
        esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
        esp_wifi_set_promiscuous(true);
        s_channel = s_connected_channel;
        esp_wifi_set_channel(s_channel, second_chan());
        ESP_LOGI(TAG, "capturing on the associated channel %u",
                 (unsigned)s_channel);
    }
    return ESP_OK;
}

/* Pulls data down from the gateway so the access point has something to send.
 *
 * 802.11ax is used for data frames, not for beacons or management, so an
 * associated but idle client never sees a single HE frame. Repeated small
 * fetches from the gateway's own web interface produce a steady stream of
 * downlink frames, and every home router has one. Failures are ignored on
 * purpose: this is a load generator, not a client, and a refused connection
 * still costs the access point a few frames to say so. */
static void traffic_task(void *arg)
{
    (void)arg;
    /* Escapes written explicitly: a carriage return and line feed pair,
     * twice, ending the request line and the header block. */
    const char *request = "GET / HTTP/1.0\r\n\r\n";
    uint8_t scratch[512];

    while (true) {
        if (!s_traffic_wanted || s_gateway == 0) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        struct sockaddr_in to = {
            .sin_family = AF_INET,
            .sin_port = htons(80),
            .sin_addr.s_addr = s_gateway,
        };
        if (connect(sock, (struct sockaddr *)&to, sizeof(to)) == 0) {
            send(sock, request, strlen(request), 0);
            int n;
            while ((n = recv(sock, scratch, sizeof(scratch), 0)) > 0) {
                s_traffic_bytes += (uint32_t)n;
            }
        }
        close(sock);
        /* A brief pause so this is a steady trickle rather than a flood of
         * connections the router may start refusing. */
        vTaskDelay(pdMS_TO_TICKS(150));
    }
}

esp_err_t sn_radio80211_set_traffic(bool enable)
{
    if (enable && s_traffic_task == NULL) {
        /* Below the USB sender and the capture task: generating load must
         * never come at the cost of the capture it exists to feed. */
        if (xTaskCreate(traffic_task, "sn_traffic", 4096, NULL, 5,
                        &s_traffic_task) != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }
    s_traffic_wanted = enable;
    ESP_LOGI(TAG, "downlink traffic generation %s",
             enable ? "on" : "off");
    return ESP_OK;
}

uint32_t sn_radio80211_traffic_bytes(void)
{
    return s_traffic_bytes;
}

void sn_radio80211_disconnect(void)
{
    s_traffic_wanted = false;
    esp_wifi_disconnect();
    s_connected_channel = 0;
}

esp_err_t sn_radio80211_station_mode(bool enable)
{
    esp_err_t err = wifi_init_once();
    if (err != ESP_OK) {
        return err;
    }
    err = esp_wifi_set_mode(enable ? WIFI_MODE_STA : WIFI_MODE_NULL);
    ESP_LOGI(TAG, "mode -> %s: %s", enable ? "STA" : "NULL",
             esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }
    /* Re-arm promiscuous after the mode change: a mode switch is exactly the
     * kind of thing that quietly clears it, and a capture that has stopped
     * delivering while reporting success is the failure this project keeps
     * running into. */
    if (s_running) {
        esp_wifi_set_promiscuous_rx_cb(promiscuous_cb);
        err = esp_wifi_set_promiscuous(true);
        ESP_LOGI(TAG, "promiscuous re-armed: %s", esp_err_to_name(err));
        if (err == ESP_OK) {
            err = esp_wifi_set_channel(s_channel, second_chan());
        }
    }
    return err;
}

esp_err_t sn_radio80211_set_snaplen(uint16_t snaplen)
{
    if (snaplen == 0u || snaplen > MAX_SNAPLEN) {
        return ESP_ERR_INVALID_ARG;
    }
    s_snaplen = snaplen;
    ESP_LOGI(TAG, "snaplen now %u", (unsigned)snaplen);
    return ESP_OK;
}

esp_err_t sn_radio80211_set_filter(uint32_t filter_mask)
{
    s_filter_mask = filter_mask;
    if (!s_running) {
        return ESP_OK; /* remembered, applied when capture starts */
    }
    esp_err_t err = apply_filter(filter_mask);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "filter now 0x%08x", (unsigned)filter_mask);
    }
    return err;
}

static esp_err_t sn_radio80211_start_inner(uint8_t channel, uint16_t snaplen,
                                           uint32_t filter_mask)
{
    if (channel < SN_80211_CHANNEL_MIN || channel > SN_80211_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    /* Zero means "keep whatever SET_SNAPLEN configured".
     *
     * This used to substitute the default, and the command handler passed a
     * hard-coded 256, so every SET_SNAPLEN was silently overwritten the moment
     * a channel was selected. The snapshot length never changed and nothing
     * said so; the self-test caught it by measuring record sizes rather than
     * trusting the reply. */
    if (snaplen > MAX_SNAPLEN) {
        snaplen = DEFAULT_SNAPLEN;
    }
    if (snaplen != 0) {
        s_snaplen = snaplen;
    }

    if (s_running) {
        return sn_radio80211_set_channel(channel);
    }

    if (s_rx_queue == NULL) {
        s_rx_queue = xQueueCreate(RX_QUEUE_LEN, sizeof(rx_item_t));
        if (s_rx_queue == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_rx_task == NULL) {
        /* Below the USB sender so draining the link always wins. */
        if (xTaskCreate(rx_task, "sn_80211", 4096, NULL, 9, &s_rx_task)
                != pdPASS) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t init_err = wifi_init_once();
    if (init_err != ESP_OK) {
        return init_err;
    }
    /* NULL mode: we never associate, only listen. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    /* start() powers up the PHY. ESP-IDF's simple_sniffer example omits it,
     * which misled me into removing it; without it the driver accepts a
     * channel, reports ic_enable_sniffer, and never invokes the callback
     * once. Measured: callback count stayed at exactly 0. */
    ESP_ERROR_CHECK(esp_wifi_start());

    /* Likewise zero means "keep", so SET_FILTER survives a channel change. */
    if (filter_mask != 0u) {
        s_filter_mask = filter_mask;
    }
    ESP_ERROR_CHECK(apply_filter(s_filter_mask));
    if (s_ctrl_filter != 0u) {
        wifi_promiscuous_filter_t ctrl = {.filter_mask = s_ctrl_filter};
        ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&ctrl));
    }
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(promiscuous_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_channel(channel, second_chan()));

    s_channel = channel;
    s_running = true;
    if (s_csi_enabled) {
        /* Re-applied here so it survives a driver rebuild after a stall. */
        esp_err_t csi_err = sn_radio80211_set_csi(true);
        if (csi_err != ESP_OK) {
            ESP_LOGW(TAG, "CSI could not be re-enabled: %s",
                     esp_err_to_name(csi_err));
        }
    }
    ESP_LOGI(TAG, "capturing on channel %u, snaplen %u",
             (unsigned)channel, (unsigned)s_snaplen);
    return ESP_OK;
}

esp_err_t sn_radio80211_set_channel(uint8_t channel)
{
    if (channel < SN_80211_CHANNEL_MIN || channel > SN_80211_CHANNEL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!s_running) {
        return sn_radio80211_start(channel, s_snaplen, SN_80211_FILTER_ALL);
    }
    esp_err_t err = esp_wifi_set_channel(channel, second_chan());
    if (err == ESP_OK) {
        s_channel = channel;
        ESP_LOGI(TAG, "channel now %u", (unsigned)channel);
    }
    return err;
}

esp_err_t sn_radio80211_start(uint8_t channel, uint16_t snaplen,
                              uint32_t filter_mask)
{
    /* arg8: 1 for a cold start, 2 for a retune of a running capture. The
     * toolbar retunes without restarting, and the two costing the same would
     * mean the retune is not the cheap operation it is sold as. */
    const uint8_t kind = s_running ? 2u : 1u;
    sn_trace(SN_TRACE_WIFI_START_IN, kind, channel);
    const esp_err_t err = sn_radio80211_start_inner(channel, snaplen,
                                                    filter_mask);
    sn_trace(SN_TRACE_WIFI_START_OUT, kind, (uint16_t)err);
    return err;
}

void sn_radio80211_stop(void)
{
    sn_trace(SN_TRACE_WIFI_STOP_IN, s_running ? 1 : 0, 0);
    if (!s_running) {
        sn_trace(SN_TRACE_WIFI_STOP_OUT, 0, 0);
        return;
    }
    esp_wifi_set_promiscuous(false);
    s_running = false;
    s_stats.stalled_seconds = 0;
    sn_trace(SN_TRACE_WIFI_STOP_OUT, 1, 0);
    ESP_LOGI(TAG, "capture stopped");
}

bool sn_radio80211_service(void)
{
    if (!s_running) {
        s_stats.stalled_seconds = 0;
        s_last_seen_callbacks = s_stats.callbacks;
        return false;
    }

    if (s_stats.callbacks != s_last_seen_callbacks) {
        s_last_seen_callbacks = s_stats.callbacks;
        s_stats.stalled_seconds = 0;
        s_stall_limit = SN_80211_STALL_LIMIT_S; /* it is alive; start over */
        return false;
    }

    /* Nothing delivered since the last tick. On 2.4 GHz that is already odd:
     * neighbouring access points beacon roughly every 100 ms, so even an
     * unused channel is not silent for long. */
    s_stats.stalled_seconds++;
    if (s_stats.stalled_seconds < s_stall_limit) {
        return false;
    }

    /* Rebuild the driver completely rather than just re-arming promiscuous
     * mode.
     *
     * Measured: this does NOT clear the deafness on this board. Three
     * consecutive rebuilds left callbacks at exactly 0, so the fault is below
     * the driver, and a full erase-flash does not clear it either. The rebuild
     * is kept because it does fix an ordinary driver-level stall, and because
     * the attempt is what makes the condition visible -- but it backs off
     * rather than tearing the stack down every 15 seconds indefinitely.
     *
     * This is a workaround for a fault that is not ours: Espressif's own
     * unmodified scan binary goes deaf on this board too. It is reported in
     * the counters rather than hidden. If recoveries climb while frames do
     * not, the radio is the problem, not the code. */
    const uint8_t channel = s_channel;
    const uint16_t snaplen = s_snaplen;
    const uint32_t filter = s_filter_mask;

    ESP_LOGW(TAG, "no frames for %us on channel %u; rebuilding the driver",
             (unsigned)s_stats.stalled_seconds, (unsigned)channel);

    esp_wifi_set_promiscuous(false);
    esp_wifi_stop();
    esp_wifi_deinit();
    s_wifi_inited = false;
    s_running = false;
    s_stats.stalled_seconds = 0;
    s_stats.recoveries++;
    /* The rebuild restarts the radio's counter. Carry the elapsed time forward
     * so timestamps keep increasing across a recovery instead of jumping back
     * to zero mid-capture. */
    s_ts_epoch += s_ts_last;
    s_ts_last = 0;

    esp_err_t err = sn_radio80211_start(channel, snaplen, filter);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "rebuild failed: %s", esp_err_to_name(err));
    }
    s_last_seen_callbacks = s_stats.callbacks;

    /* Back off, capped, so a persistent fault costs one rebuild a minute
     * rather than four. Any frame at all resets this. */
    if (s_stall_limit < SN_80211_STALL_LIMIT_MAX_S) {
        s_stall_limit *= 2u;
        if (s_stall_limit > SN_80211_STALL_LIMIT_MAX_S) {
            s_stall_limit = SN_80211_STALL_LIMIT_MAX_S;
        }
    }
    return true;
}

uint8_t sn_radio80211_channel(void)
{
    return s_channel;
}

void sn_radio80211_get_stats(sn_80211_stats_t *out)
{
    *out = s_stats;
}

esp_err_t sn_radio80211_scan(uint16_t *out_ap_count, bool active)
{
    if (out_ap_count == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_ap_count = 0;

    /* Bring the driver up if capture has not already done it. Skipping this
     * was the defect described on wifi_init_once(). */
    esp_err_t err = wifi_init_once();
    ESP_LOGI(TAG, "scan: wifi_init_once -> %s", esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }

    /* Scanning needs station mode; promiscuous capture uses NULL mode.
     * Every step is logged with its error code: a bare failure return told us
     * nothing about which call was refusing. */
    err = esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "scan: set_promiscuous(false) -> %s", esp_err_to_name(err));

    err = esp_wifi_set_mode(WIFI_MODE_STA);
    ESP_LOGI(TAG, "scan: set_mode(STA) -> %s", esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }

    err = esp_wifi_start();
    ESP_LOGI(TAG, "scan: wifi_start -> %s", esp_err_to_name(err));
    if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
        return err;
    }

    /* Explicit dwell times. A zeroed config means zero milliseconds per
     * channel, and a scan that never lingers finds nothing however loud the
     * air is -- a broken instrument that looks like a broken radio. */
    wifi_scan_config_t cfg = {0};
    cfg.show_hidden = true;
    if (active) {
        /* Transmits probe requests. Faster, and it finds access points that
         * are not beaconing at that moment -- but it makes the sniffer visible
         * on the air, which is the opposite of what this instrument is for.
         * Opt-in only, never the default. */
        cfg.scan_type = WIFI_SCAN_TYPE_ACTIVE;
        cfg.scan_time.active.min = 120;
        cfg.scan_time.active.max = 400;
    } else {
        /* Listens for beacons and transmits nothing. The dwell has to exceed a
         * beacon interval, which is about 100 ms, or a passive scan misses the
         * very networks it is looking for. */
        cfg.scan_type = WIFI_SCAN_TYPE_PASSIVE;
        cfg.scan_time.passive = 150;
    }
    err = esp_wifi_scan_start(&cfg, true); /* blocking */
    ESP_LOGI(TAG, "scan: scan_start (%s) -> %s",
             active ? "active, transmitting probes" : "passive",
             esp_err_to_name(err));
    if (err != ESP_OK) {
        return err;
    }
    uint16_t n = 0;
    err = esp_wifi_scan_get_ap_num(&n);
    if (err != ESP_OK) {
        return err;
    }
    *out_ap_count = n;
    ESP_LOGI(TAG, "scan found %u access points", (unsigned)n);
    if (n == 0) {
        return ESP_OK;
    }

    /* Fetched in small batches rather than all at once: wifi_ap_record_t is
     * around 700 bytes here, so a busy area would otherwise need tens of
     * kilobytes of heap on a chip with a few hundred. */
    static const uint16_t BATCH = 4;
    wifi_ap_record_t *records = calloc(BATCH, sizeof(wifi_ap_record_t));
    if (records == NULL) {
        return ESP_ERR_NO_MEM;
    }

    uint16_t remaining = n;
    while (remaining > 0) {
        uint16_t want = (remaining > BATCH) ? BATCH : remaining;
        /* esp_wifi_scan_get_ap_records() drains the list, so each call returns
         * the next batch and the results are freed as they go. */
        if (esp_wifi_scan_get_ap_records(&want, records) != ESP_OK || want == 0) {
            break;
        }
        for (uint16_t i = 0; i < want; i++) {
            uint8_t out[SN_80211_AP_RECORD_HEADER + 32];
            size_t ssid_len = strnlen((const char *)records[i].ssid, 32);
            out[0] = (uint8_t)records[i].rssi;
            out[1] = records[i].primary;
            out[2] = (uint8_t)records[i].authmode;
            out[3] = (uint8_t)ssid_len;
            memcpy(out + 4, records[i].bssid, 6);
            memcpy(out + SN_80211_AP_RECORD_HEADER, records[i].ssid, ssid_len);
            /* Blocking: a scan result is small, rare, and worth waiting for.
             * Dropping it would leave the host with a count it cannot explain. */
            sn_usb_link_send_wait(SN_FRAME_AP_RECORD, out,
                                  SN_80211_AP_RECORD_HEADER + ssid_len, 1000);
        }
        remaining -= want;
    }
    free(records);
    return ESP_OK;
}
