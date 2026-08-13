#include "lwip/sockets.h"
#include "FreeRTOS.h"
#include "task.h"
#include "easyflash.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

// Helper function to safely read EasyFlash env variables into local buffers immediately
static void get_env_str(const char *key, char *dst, size_t max_len, const char *default_val) {
    const char *val = ef_get_env(key);
    if (val && *val != '\0') {
        strncpy(dst, val, max_len - 1);
        dst[max_len - 1] = '\0';
    } else {
        strncpy(dst, default_val, max_len - 1);
        dst[max_len - 1] = '\0';
    }
}

// Helper function to convert a single hex character to its integer value
static int hex_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void url_decode(char *dst, const char *src, size_t max_len) {
    size_t i = 0;
    while (*src && i < max_len - 1) {
        if (*src == '+') {
            dst[i++] = ' ';
            src++;
        } else if (*src == '%' && src[1] && src[2]) {
            int h1 = hex_to_val(src[1]);
            int h2 = hex_to_val(src[2]);
            
            if (h1 >= 0 && h2 >= 0) {
                dst[i++] = (char)((h1 << 4) | h2);
                src += 3;
            } else {
                dst[i++] = *src++;
            }
        } else {
            dst[i++] = *src++;
        }
    }
    dst[i] = '\0';
}

static bool get_form_field(const char *body, const char *key, char *out_val, size_t max_len) {
    char search_pattern[48];
    snprintf(search_pattern, sizeof(search_pattern), "%s=", key);
    
    char *p = strstr(body, search_pattern);
    if (!p) {
        out_val[0] = '\0';
        return false;
    }

    p += strlen(search_pattern);
    char raw_buf[128];
    size_t len = 0;

    while (p[len] != '\0' && p[len] != '&' && len < sizeof(raw_buf) - 1) {
        raw_buf[len] = p[len];
        len++;
    }
    raw_buf[len] = '\0';

    url_decode(out_val, raw_buf, max_len);
    return true;
}

static void http_server_task(void *pvParameters) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        vTaskDelete(NULL);
        return;
    }

    int enable = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(server_fd);
        vTaskDelete(NULL);
        return;
    }

    listen(server_fd, 5);

    char *rx_buf = pvPortMalloc(1024);
    char *body = pvPortMalloc(1024);
    char header[128];

    if (!rx_buf || !body) {
        if (rx_buf) vPortFree(rx_buf);
        if (body) vPortFree(body);
        close(server_fd);
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        memset(rx_buf, 0, 1024);
        int read_len = read(client_fd, rx_buf, 1023);

        if (read_len > 0) {
            rx_buf[read_len] = '\0';

            if (strstr(rx_buf, "GET /favicon.ico")) {
                const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                send(client_fd, not_found, strlen(not_found), 0);
                close(client_fd);
                continue;
            }

            if (strncmp(rx_buf, "POST", 4) == 0) {
                char *body_start = strstr(rx_buf, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    char val_buf[64];

                    if (get_form_field(body_start, "UpstreamSSID", val_buf, sizeof(val_buf))) {
                        printf("saving... %s\n", val_buf);
                        ef_set_env("UpstreamSSID", val_buf);
                    }
                    if (get_form_field(body_start, "UpstreamPSK", val_buf, sizeof(val_buf))) {
                        printf("saving... %s\n", val_buf);
                        ef_set_env("UpstreamPSK", val_buf);
                    }
                    if (get_form_field(body_start, "DeviceSSID", val_buf, sizeof(val_buf))) {
                        printf("saving... %s\n", val_buf);
                        ef_set_env("DeviceSSID", val_buf);
                    }
                    if (get_form_field(body_start, "DevicePSK", val_buf, sizeof(val_buf))) {
                        printf("saving... %s\n", val_buf);
                        ef_set_env("DevicePSK", val_buf);
                    }

                    bool ui_checked = get_form_field(body_start, "EnableUI", val_buf, sizeof(val_buf));
                    ef_set_env("EnableUI", ui_checked ? "1" : "0");

                    ef_save_env();
                }
            }

            // Dedicated local stack buffers to copy static EasyFlash values immediately
            char up_ssid[33];
            char up_psk[65];
            char dev_ssid[33];
            char dev_psk[65];
            char enable_ui[4];

            get_env_str("UpstreamSSID", up_ssid, sizeof(up_ssid), "");
            get_env_str("UpstreamPSK", up_psk, sizeof(up_psk), "");
            get_env_str("DeviceSSID", dev_ssid, sizeof(dev_ssid), "BL602_Node");
            get_env_str("DevicePSK", dev_psk, sizeof(dev_psk), "12345678");
            get_env_str("EnableUI", enable_ui, sizeof(enable_ui), "0");

            bool is_ui_enabled = (strcmp(enable_ui, "1") == 0);

            int body_len = snprintf(body, 1024,
                "<!DOCTYPE html><html><body>"
                "<h2>BL602 Wi-Fi & Device Settings</h2>"
                "<form action=\"/\" method=\"post\">"
                "  <h3>Upstream Network (Client)</h3>"
                "  <label>SSID:</label><br>"
                "  <input type=\"text\" name=\"UpstreamSSID\" value=\"%s\"><br>"
                "  <label>Password:</label><br>"
                "  <input type=\"password\" name=\"UpstreamPSK\" value=\"%s\"><br><br>"
                "  <h3>Local Access Point (AP)</h3>"
                "  <label>Device SSID:</label><br>"
                "  <input type=\"text\" name=\"DeviceSSID\" value=\"%s\"><br>"
                "  <label>Device Password:</label><br>"
                "  <input type=\"password\" name=\"DevicePSK\" value=\"%s\"><br><br>"
                "  <h3>UI Settings</h3>"
                "  <input type=\"checkbox\" name=\"EnableUI\" value=\"1\" %s>"
                "  <label for=\"EnableUI\"> Enable Web UI</label><br><br>"
                "  <input type=\"submit\" value=\"Save Settings\">"
                "</form>"
                "</body></html>",
                up_ssid, up_psk, dev_ssid, dev_psk,
                is_ui_enabled ? "checked" : ""
            );

            int header_len = snprintf(header, sizeof(header),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n\r\n",
                body_len
            );

            send(client_fd, header, header_len, 0);
            send(client_fd, body, body_len, 0);
        }

        close(client_fd);
    }
}

void start_webserver_task(void) {
    xTaskCreate(
        http_server_task, 
        "HTTP_Server", 
        4096, 
        NULL, 
        tskIDLE_PRIORITY + 2, 
        NULL
    );
}