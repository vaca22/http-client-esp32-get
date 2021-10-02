/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "esp_log.h"
#include "nvs_flash.h"
/* BLE */
#include "bleprph.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "nvs_flash.h"
#include <string.h>

#include "lwip/err.h"
#include "lwip/sys.h"

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include <string.h>
#include <sys/param.h>

#include "addr_from_stdin.h"
#include "lwip/err.h"
#include "lwip/sockets.h"

#include "esp_event_loop.h"
#include "freertos/semphr.h"

#include "driver/mcpwm.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "protocol_examples_common.h"
#include "string.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"
#include <sys/socket.h>

#define HASH_LEN 32

#include "esp_camera.h"

// WROVER-KIT PIN Map
#define CAM_PIN_PWDN 32  // power down is not used
#define CAM_PIN_RESET 32 // software reset will be performed
#define CAM_PIN_XCLK 0
#define CAM_PIN_SIOD 26
#define CAM_PIN_SIOC 27

#define CAM_PIN_D7 35
#define CAM_PIN_D6 34
#define CAM_PIN_D5 39
#define CAM_PIN_D4 36
#define CAM_PIN_D3 21
#define CAM_PIN_D2 19
#define CAM_PIN_D1 18
#define CAM_PIN_D0 5
#define CAM_PIN_VSYNC 25
#define CAM_PIN_HREF 23
#define CAM_PIN_PCLK 22

static camera_config_t camera_config = {
    .pin_pwdn = CAM_PIN_PWDN,
    .pin_reset = CAM_PIN_RESET,
    .pin_xclk = CAM_PIN_XCLK,
    .pin_sscb_sda = CAM_PIN_SIOD,
    .pin_sscb_scl = CAM_PIN_SIOC,

    .pin_d7 = CAM_PIN_D7,
    .pin_d6 = CAM_PIN_D6,
    .pin_d5 = CAM_PIN_D5,
    .pin_d4 = CAM_PIN_D4,
    .pin_d3 = CAM_PIN_D3,
    .pin_d2 = CAM_PIN_D2,
    .pin_d1 = CAM_PIN_D1,
    .pin_d0 = CAM_PIN_D0,
    .pin_vsync = CAM_PIN_VSYNC,
    .pin_href = CAM_PIN_HREF,
    .pin_pclk = CAM_PIN_PCLK,

    .xclk_freq_hz = 20000000, // EXPERIMENTAL: Set to 16MHz on ESP32-S2 or
                              // ESP32-S3 to enable EDMA mode
    .ledc_timer = LEDC_TIMER_0,
    .ledc_channel = LEDC_CHANNEL_0,

    .pixel_format = PIXFORMAT_JPEG, // YUV422,GRAYSCALE,RGB565,JPEG
    .frame_size =
        FRAMESIZE_SVGA, // QQVGA-QXGA Do not use sizes above QVGA when not JPEG

    .jpeg_quality = 12, // 0-63 lower number means higher quality
    .fb_count =2, // if more than one, i2s runs in continuous mode. Use only with JPEG
    .grab_mode = CAMERA_GRAB_WHEN_EMPTY // CAMERA_GRAB_LATEST. Sets when buffers
                                        // should be filled
};

esp_err_t camera_init() {
    // power up the camera if PWDN pin is defined

    // initialize the camera
    esp_err_t err = esp_camera_init(&camera_config);
    if (err != ESP_OK) {
        printf("Camera Init Failed");
        return err;
    }

    return ESP_OK;
}

static TaskHandle_t print_task_h;
static TaskHandle_t send_task_h;
static TaskHandle_t ota_task_h;
static TaskHandle_t receive_task_h;

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
/* The interface name value can refer to if_desc in esp_netif_defaults.h */
#if CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF_ETH
static const char *bind_interface_name = "eth";
#elif CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF_STA
static const char *bind_interface_name = "sta";
#endif
#endif

static const char *TAG = "simple_ota_example";
int fuck = 0;
int fuck2 = 0;
int fuck3 = 0;

#define OTA_URL_SIZE 256

esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key,
                 evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    }
    return ESP_OK;
}

void simple_ota_example_task(void *pvParameter) {
    vTaskSuspend(NULL);
    ESP_LOGI(TAG, "Starting OTA example");
#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
    esp_netif_t *netif = get_example_netif_from_desc(bind_interface_name);
    if (netif == NULL) {
        ESP_LOGE(TAG, "Can't find netif from interface description");
        abort();
    }
    struct ifreq ifr;
    esp_netif_get_netif_impl_name(netif, ifr.ifr_name);
    ESP_LOGI(TAG, "Bind interface name is %s", ifr.ifr_name);
#endif
    esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL,
        .event_handler = _http_event_handler,
        .keep_alive_enable = true,
#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
        .if_name = &ifr,
#endif
    };

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL_FROM_STDIN
    char url_buf[OTA_URL_SIZE];
    if (strcmp(config.url, "FROM_STDIN") == 0) {
        example_configure_stdin_stdout();
        fgets(url_buf, OTA_URL_SIZE, stdin);
        int len = strlen(url_buf);
        url_buf[len - 1] = '\0';
        config.url = url_buf;
    } else {
        ESP_LOGE(TAG,
                 "Configuration mismatch: wrong firmware upgrade image url");
        abort();
    }
#endif

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
    config.skip_cert_common_name_check = true;
#endif

    esp_err_t ret = esp_https_ota(&config);
    if (ret == ESP_OK) {
        esp_restart();
    } else {
        ESP_LOGE(TAG, "Firmware upgrade failed");
    }
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

static void print_sha256(const uint8_t *image_hash, const char *label) {
    char hash_print[HASH_LEN * 2 + 1];
    hash_print[HASH_LEN * 2] = 0;
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
    }
    ESP_LOGI(TAG, "%s %s", label, hash_print);
}

static void get_sha256_of_partitions(void) {
    uint8_t sha_256[HASH_LEN] = {0};
    esp_partition_t partition;

    // get sha256 digest for bootloader
    partition.address = ESP_BOOTLOADER_OFFSET;
    partition.size = ESP_PARTITION_TABLE_OFFSET;
    partition.type = ESP_PARTITION_TYPE_APP;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for bootloader: ");

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    print_sha256(sha_256, "SHA-256 for current firmware: ");
}

#define SERVO_MIN_PULSEWIDTH_US (1000) // Minimum pulse width in microsecond
#define SERVO_MAX_PULSEWIDTH_US (2000) // Maximum pulse width in microsecond
#define SERVO_MAX_DEGREE                                                       \
    (90) // Maximum angle in degree upto which servo can rotate

#define SERVO_PULSE_GPIO1 (15) // GPIO connects to the PWM signal line
#define SERVO_PULSE_GPIO2 (14) // GPIO connects to the PWM signal line
static inline uint32_t example_convert_servo_angle_to_duty_us(int angle) {
    return (angle + SERVO_MAX_DEGREE) *
               (SERVO_MAX_PULSEWIDTH_US - SERVO_MIN_PULSEWIDTH_US) /
               (2 * SERVO_MAX_DEGREE) +
           SERVO_MIN_PULSEWIDTH_US;
}

#define HOST_IP_ADDR "81.71.163.52"

#define PORT 5555
static const char *payload = "Message from ESP32 ";

#define EXAMPLE_ESP_WIFI_SSID "vaca"
#define EXAMPLE_ESP_WIFI_PASS "22345678"
#define EXAMPLE_ESP_MAXIMUM_RETRY 32

static EventGroupHandle_t s_wifi_event_group;
/* The event group allows multiple bits for each event, but we only care about
 * two events:
 * - we are connected to the AP with an IP
 * - we failed to connect after the maximum amount of retries */
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

static int s_retry_num = 0;

#define CMD_READ_FILE_DATA 0xF3

static unsigned char sendBuf[60000];
unsigned char crc8_compute(unsigned char *pdata, unsigned data_size,
                           unsigned char crc_in);
void ReplyFileData(unsigned char *contents, int len, unsigned char *mother) {
    mother[0] = (unsigned char)0xA5;
    mother[1] = (unsigned char)CMD_READ_FILE_DATA;
    mother[2] = (unsigned char)~CMD_READ_FILE_DATA;
    mother[3] = (unsigned char)0;
    mother[4] = 0;
    mother[5] = 0;

    mother[6] = len & 0xff;
    mother[7] = (len >> 8) & 0xff;
    mother[8] = (len >> 16) & 0xff;
    mother[9] = (len >> 24) & 0xff;
    for (int k = 0; k < len; k++) {
        mother[10 + k] = contents[k];
    }
    mother[10 + len] = crc8_compute(mother, 10 + len, 0);
}

unsigned char crc8_compute(unsigned char *pdata, unsigned data_size,
                           unsigned char crc_in) {
    uint8_t cnt;
    uint8_t crc_poly = 0x07;
    uint8_t data_tmp = 0;

    while (data_size--) {
        data_tmp = *(pdata++);
        crc_in ^= (data_tmp << 0);

        for (cnt = 0; cnt < 8; cnt++) {
            if (crc_in & 0x80) {
                crc_in = (crc_in << 1) ^ crc_poly;
            } else {
                crc_in = crc_in << 1;
            }
        }
    }

    return crc_in;
}
int sock;

static void tcp_client_task(void *pvParameters) {
    char rx_buffer[128];
    char host_ip[] = HOST_IP_ADDR;
    int addr_family = 0;
    int ip_protocol = 0;

    while (1) {

        if (fuck) {

            struct sockaddr_in dest_addr;
            dest_addr.sin_addr.s_addr = inet_addr(host_ip);
            dest_addr.sin_family = AF_INET;
            dest_addr.sin_port = htons(PORT);
            addr_family = AF_INET;
            ip_protocol = IPPROTO_IP;

            sock = socket(addr_family, SOCK_STREAM, ip_protocol);
            if (sock < 0) {
                ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
                break;
            }
            ESP_LOGI(TAG, "Socket created, connecting to %s:%d", host_ip, PORT);

            int err = connect(sock, (struct sockaddr *)&dest_addr,
                              sizeof(struct sockaddr_in6));
            if (err != 0) {
                ESP_LOGE(TAG, "Socket unable to connect: errno %d", errno);
                break;
            }
            ESP_LOGI(TAG, "Successfully connected");
            fuck2 = 1;
            while (1) {

                camera_fb_t *fb = esp_camera_fb_get();
                if (!fb) {
                    continue;
                }
                ReplyFileData(fb->buf, fb->len, sendBuf);
                send(sock, sendBuf, 11 + (fb->len), 0);
                esp_camera_fb_return(fb);

                // vTaskDelay(10 / portTICK_PERIOD_MS);
            }
        }
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }
    vTaskDelete(NULL);
}

unsigned char tcpReceive[10000];
int currentIndex = 0;
unsigned char tcpcmd[100];

void po2(int size) {
    unsigned int a;
    unsigned int b;
    switch (tcpcmd[1]) {
    case 0xf4:
        a = tcpcmd[10] + tcpcmd[11] * 256;
        b = tcpcmd[12] + tcpcmd[13] * 256;
        ESP_LOGI(TAG, "leaft %d    right   %d", a, b);
        mcpwm_set_duty_in_us(MCPWM_UNIT_0, MCPWM_TIMER_0, MCPWM_OPR_A, a);
        mcpwm_set_duty_in_us(MCPWM_UNIT_0, MCPWM_TIMER_0, MCPWM_OPR_B, b);
        break;

    case 0xf5:
        ESP_LOGI(TAG, "fuckReceivegggggggggggg");
        vTaskSuspend(send_task_h);
        // vTaskSuspend(receive_task_h);
        vTaskDelete(send_task_h);
        // vTaskDelete(receive_task_h);
        vTaskResume(ota_task_h);
        ESP_LOGI(TAG, "fuckReceivehhhhhhhhhhhh");
        break;

    default:
        break;
    }
}

void poces() {
    int size = currentIndex + 1;
    int len;
    int con = 0;
    while (1) {
        if (currentIndex < 11) {
            return;
        }
        size = currentIndex + 1;
        con = 0;
        for (int i = 0; i < size - 10; i++) {
            if (tcpReceive[i] == 0xa5 &&
                tcpReceive[i + 1] == ((unsigned char)(~tcpReceive[i + 2]))) {
                len = tcpReceive[i + 6];
                if (i + 11 + len <= size) {
                    for (int j = 0; j < len + 11; j++) {
                        tcpcmd[j] = tcpReceive[i + j];
                    }
                    if (crc8_compute(tcpcmd, len + 10, 0) == tcpcmd[len + 10]) {
                        po2(len + 11);
                        if (i + 11 + len == size) {
                            currentIndex = 0;
                        } else {
                            for (int gg = i + 11 + len; gg < size; gg++) {
                                tcpReceive[gg - i - 11 - len] = tcpReceive[gg];
                            }
                            currentIndex = currentIndex - i - 11 - len;
                        }

                        con = 1;
                    }
                }
            }
        }
        if (con == 0) {
            return;
        }
    }
}

static void tcp_client_task2(void *pvParameters) {
    unsigned char rx_buffer[128];
    int k;

    while (fuck2 != 1) {
        vTaskDelay(500 / portTICK_PERIOD_MS);
    }

    while (1) {
        int len = recv(sock, rx_buffer, sizeof(rx_buffer) - 1, 0);
        // Error occurred during receiving
        if (len < 0) {
            ESP_LOGE(TAG, "recv failed: errno %d", errno);
            break;
        }
        // Data received
        else {
            ESP_LOGI(TAG, "fuckReceive");
            for (k = 0; k < len; k++) {
                tcpReceive[currentIndex + k] = rx_buffer[k];
            }
            currentIndex += len;
            if (currentIndex > 9000) {
                currentIndex = 0;
            }
            poces();
        }

        vTaskDelay(5 / portTICK_PERIOD_MS);
    }
}

static void event_handler(void *arg, esp_event_base_t event_base,
                          int32_t event_id, void *event_data) {
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT &&
               event_id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_num < EXAMPLE_ESP_MAXIMUM_RETRY) {
            esp_wifi_connect();
            s_retry_num++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        } else {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "connect to the AP fail");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_num = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void wifi_init_sta(void) {
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta =
            {
                .ssid = EXAMPLE_ESP_WIFI_SSID,
                .password = EXAMPLE_ESP_WIFI_PASS,
                /* Setting a password implies station will connect to all
                 * security modes including WEP/WPA. However these modes are
                 * deprecated and not advisable to be used. Incase your Access
                 * point doesn't support WPA2, these mode can be enabled by
                 * commenting below line */
                .threshold.authmode = WIFI_AUTH_WPA2_PSK,

                .pmf_cfg = {.capable = true, .required = false},
            },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    /* Waiting until either the connection is established (WIFI_CONNECTED_BIT)
     * or connection failed for the maximum
     * number of re-tries (WIFI_FAIL_BIT). The bits are set by event_handler()
     * (see above) */
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
                                           WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE, portMAX_DELAY);

    /* xEventGroupWaitBits() returns the bits before the call returned, hence we
     * can test which event actually happened. */
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "connected to ap SSID:%s password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);

        fuck = 1;

    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGI(TAG, "Failed to connect to SSID:%s, password:%s",
                 EXAMPLE_ESP_WIFI_SSID, EXAMPLE_ESP_WIFI_PASS);

    } else {
        ESP_LOGE(TAG, "UNEXPECTED EVENT");
    }

    /* The event will not be processed after unregister */
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(
        WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
    vEventGroupDelete(s_wifi_event_group);
}

#define PRINT_CORE tskNO_AFFINITY
static const char *tag = "Snake";

void app_main(void) {

    /* Initialize NVS it is used to store PHY calibration data */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    camera_init();

    mcpwm_gpio_init(MCPWM_UNIT_0, MCPWM0A,
                    SERVO_PULSE_GPIO1); // To drive a RC servo, one MCPWM
                                        // generator is enough
    mcpwm_gpio_init(MCPWM_UNIT_0, MCPWM0B, SERVO_PULSE_GPIO2);
    mcpwm_config_t pwm_config = {
        .frequency = 50, // frequency = 50Hz, i.e. for every servo motor time
                         // period should be 20ms
        .cmpr_a = 0,     // duty cycle of PWMxA = 0
        .counter_mode = MCPWM_UP_COUNTER,
        .duty_mode = MCPWM_DUTY_MODE_0,
    };
    mcpwm_init(MCPWM_UNIT_0, MCPWM_TIMER_0, &pwm_config);

    mcpwm_set_duty_in_us(MCPWM_UNIT_0, MCPWM_TIMER_0, MCPWM_OPR_A, 1500);
    mcpwm_set_duty_in_us(MCPWM_UNIT_0, MCPWM_TIMER_0, MCPWM_OPR_B, 1500);

    wifi_init_sta();
    //     // initBle();

    esp_wifi_set_ps(WIFI_PS_NONE);

    xTaskCreate(&simple_ota_example_task, "ota_example_task", 8192, NULL, 5,
                &ota_task_h);
    xTaskCreate(tcp_client_task, "tcp_client", 4096, NULL, 5, &send_task_h);
    xTaskCreate(tcp_client_task2, "tcp_client2", 4096, NULL, 5,
                &receive_task_h);
}
