#include <stdio.h>
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "openssl/ssl.h"
#include "sys/socket.h"
#include "netdb.h"
#include "freertos/event_groups.h"
#include "driver/gpio.h"
#include "SocketIoT.h"

static const char *TAG = "ESP";
static EventGroupHandle_t wifi_event_group;

esp_err_t root_handler(httpd_req_t *req)
{
    httpd_resp_send(req, "Animesh", 7);
    return ESP_OK;
}

httpd_uri_t root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_handler,
    .user_ctx = NULL};

void start_server()
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;

    ESP_LOGI(TAG, "Starting server on port %d", config.server_port);

    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(TAG, "Server Started");
        httpd_register_uri_handler(server, &root);
    }
    else
    {
        ESP_LOGI(TAG, "Error Starting Server");
    }
}

void sendMsg(SSL *ssl, uint16_t msg_type, const char *msg, uint16_t length)
{
    SocketIoTHeader hdr = {length, msg_type};
    hdr.msg_len = htons(hdr.msg_len);
    hdr.msg_type = htons(hdr.msg_type);
    uint8_t fullbuff[length + sizeof(SocketIoTHeader)];
    memcpy(fullbuff, &hdr, sizeof(SocketIoTHeader));
    memcpy(fullbuff + sizeof(SocketIoTHeader), msg, length);
    SSL_write(ssl, fullbuff, length + sizeof(SocketIoTHeader));
}

void handle_write(uint8_t pin, char* value){
    ESP_LOGI(TAG, "Pin is %d and Value is %s", pin, value);
    gpio_set_level(GPIO_NUM_16, atoi(value));
}


void app_main()
{
    gpio_set_direction(GPIO_NUM_16, GPIO_MODE_OUTPUT);

    socketiot_init();

    if (wifi_connect("", ""))
    {
        ESP_LOGI(TAG, "WiFi Connected");
    }
    else
    {
        ESP_LOGI(TAG, "WiFi Connection Failed");
    }

    socketiotapp_t* app = socketiotapp_init("", "", 443);

    socketiotapp_register_event(app, 'w', handle_write);

    socketiotapp_connect(app);

    socketiotapp_start(app);
}