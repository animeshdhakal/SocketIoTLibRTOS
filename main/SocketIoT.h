#ifndef SocketIoT_H
#define SocketIoT_H

#include <stdint.h>
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/event_groups.h"
#include "openssl/ssl.h"
#include "esp_log.h"
#include "sys/socket.h"
#include "netdb.h"

#define HANDLER_SIZE 10
#define TASK_STACK_SIZE 8*1024
#define InfoParam(x, y) x "\0" y "\0"
#define HEARTBEAT 10000
#define Num2String(x) #x
#define NumToString(x) Num2String(x)

static const char *STAG = "SocketIoT";
static EventGroupHandle_t wifi_event_group = NULL;
typedef void(*socketiotapp_handler_t)(uint8_t pin, char* value);

typedef struct
{
    uint16_t msg_len;
    uint16_t msg_type;
} SocketIoTHeader;

typedef struct {
    char e;
    socketiotapp_handler_t handler;
} Handler;

typedef enum
{
    CONNECTING,
    CONNECTED,
    AUTH_FAILED,
    DISCONNECTED
} SocketIoTState;

typedef struct
{
    char host[50];
    uint16_t port;
    char token[36];
    SSL_CTX* ctx;
    SSL* ssl;
    SocketIoTState state;
    uint16_t last_ping;
    Handler handler[HANDLER_SIZE];
    int handlerendex;
} socketiotapp_t;

enum MsgType
{
    _,
    AUTH,
    WRITE,
    READ,
    PING,
    SYNC,
    INFO,
    SYS
};

void handle_wifi_event(void *, esp_event_base_t, int32_t, void *);
bool wifi_connect(const char*, const char*);
void socketiot_init();
socketiotapp_t* socketiotapp_init(const char* token, const char* host, uint16_t port);
void socketiotapp_connect(socketiotapp_t* app);
void socketiotapp_sendmsg(socketiotapp_t* app, uint16_t msg_type, const char *msg, uint16_t length);
void socketiotapp_start(socketiotapp_t* app);
void socketiotapp_register_event(socketiotapp_t* app, char e, socketiotapp_handler_t handler);
socketiotapp_handler_t socketiotapp_get_event(socketiotapp_t*, char e);

#endif