#include "SocketIoT.h"

void handle_wifi_event(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        xEventGroupSetBits(wifi_event_group, BIT0);
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        xEventGroupSetBits(wifi_event_group, BIT1);
    }
}

bool wifi_connect(const char *ssid, const char *password)
{
    wifi_event_group = xEventGroupCreate();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &handle_wifi_event, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &handle_wifi_event, NULL));

    wifi_config_t wifi_cfg = {};

    strcpy((char *)wifi_cfg.sta.ssid, ssid);
    strcpy((char *)wifi_cfg.sta.password, password);

    if (strlen((char *)wifi_cfg.sta.password))
    {
        wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group, BIT0 | BIT1, pdFALSE, pdFALSE, portMAX_DELAY);

    ESP_ERROR_CHECK(esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &handle_wifi_event))
    ESP_ERROR_CHECK(esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &handle_wifi_event));
    vEventGroupDelete(wifi_event_group);

    if (bits & BIT1)
    {
        return true;
    }

    return false;
}

void socketiot_init()
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
}

socketiotapp_t *socketiotapp_init(const char *token, const char *host, uint16_t port)
{
    socketiotapp_t *app = malloc(sizeof(socketiotapp_t));
    strcpy(app->host, host);
    strcpy(app->token, token);
    app->port = port;
    app->ctx = SSL_CTX_new(TLSv1_2_client_method());
    if (!app->ctx)
    {
        ESP_LOGI(STAG, "SSL Context Creation Failed");
        return NULL;
    }
    app->ssl = SSL_new(app->ctx);
    if (!app->ssl)
    {
        ESP_LOGI(STAG, "SSL Creation Failed");
        return NULL;
    }

    app->state = CONNECTING;
    app->last_ping = 0;
    app->handlerendex = -1;
    return app;
}

void socketiotapp_connect(socketiotapp_t *app)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char strport[8];
    snprintf(strport, sizeof(strport), "%u", app->port);
    getaddrinfo(app->host, strport, &hints, &res);

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    if (sockfd < 0)
    {
        ESP_LOGI(STAG, "Socket Creation Failed");
        return;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        ESP_LOGI(STAG, "Socket Connection Failed");
        return;
    }

    freeaddrinfo(res);

    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

    SSL_set_fd(app->ssl, sockfd);

    if (SSL_connect(app->ssl) < 0)
    {
        ESP_LOGI(STAG, "SSL Connection Failed");
        return;
    }

    ESP_LOGI(STAG, "Connected to SSL Server");
}

void socketiotapp_sendmsg(socketiotapp_t *app, uint16_t msg_type, const char *msg, uint16_t length)
{
    SocketIoTHeader hdr = {length, msg_type};
    hdr.msg_len = htons(hdr.msg_len);
    hdr.msg_type = htons(hdr.msg_type);
    uint8_t fullbuff[length + sizeof(SocketIoTHeader)];
    memcpy(fullbuff, &hdr, sizeof(SocketIoTHeader));
    memcpy(fullbuff + sizeof(SocketIoTHeader), msg, length);
    SSL_write(app->ssl, fullbuff, length + sizeof(SocketIoTHeader));
}

void socketiot_sendinfo(socketiotapp_t *app)
{
    static const char info[] = "info\0" InfoParam("hbeat", NumToString(HEARTBEAT)) "\0";

    size_t actualsize = sizeof(info) - 1 - 2;

    socketiotapp_sendmsg(app, INFO, info + 1, actualsize);
}

void socketiotapp_handle_write(socketiotapp_t* app, char* buff){
    uint8_t pin = atoi(buff);
    buff += strlen(buff) + 1;
    socketiotapp_handler_t handler = socketiotapp_get_event(app, 'w');
    if(handler){
        handler(pin, buff);
    }
}

void socketiotapp_task(void *arg)
{
    socketiotapp_t *app = (socketiotapp_t *)arg;
    SocketIoTHeader hdr = {};

    while(1){
        int rlen =  SSL_read(app->ssl, &hdr, sizeof(hdr));
        TickType_t now = xTaskGetTickCount();

        if(rlen == sizeof(hdr)){
            hdr.msg_len = ntohs(hdr.msg_len);
            hdr.msg_type = ntohs(hdr.msg_type);

            uint8_t buff[hdr.msg_len + 1];
            SSL_read(app->ssl, buff, hdr.msg_len);
            buff[hdr.msg_len] = 0;

            switch(hdr.msg_type){
                case AUTH:
                    if(buff[0] - '0' == 1){
                        ESP_LOGI(STAG, "Authenticated");
                        app->state = CONNECTED;
                        app->last_ping = now;
                    } else{
                        ESP_LOGI(STAG, "Authentication Failed");
                        app->state = AUTH_FAILED;
                    }
                    break;
                case WRITE:
                    socketiotapp_handle_write(app, (char*)buff);
                    break;
            }

            ESP_LOGI(STAG, "MsgLen %d and MsgType %d", hdr.msg_len, hdr.msg_type);
        }

        if(app->state == CONNECTED && ((now * portTICK_PERIOD_MS - app->last_ping * portTICK_PERIOD_MS) >= HEARTBEAT)){
            ESP_LOGI(STAG, "Sending Ping");
            socketiotapp_sendmsg(app, PING, NULL, 0);
            app->last_ping = now;
        }

        portYIELD();
    }


    vTaskDelete(NULL);
}

void socketiotapp_register_event(socketiotapp_t* app, char e, socketiotapp_handler_t h){
    Handler handler = {e, h};
    app->handler[++app->handlerendex] = handler;
}

socketiotapp_handler_t socketiotapp_get_event(socketiotapp_t* app, char e){
    for(int i = 0; i < HANDLER_SIZE; i++){
        if(app->handler[i].e == e){
            return app->handler[i].handler;
        }
    }

    return NULL;
}


void socketiotapp_start(socketiotapp_t *app)
{
    socketiotapp_sendmsg(app, AUTH, app->token, strlen(app->token));
    xTaskCreate(&socketiotapp_task, "SocketIoTTask", TASK_STACK_SIZE, app, 1, NULL);
}