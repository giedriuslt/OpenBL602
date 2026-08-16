#include "lwip/sockets.h"
#include "FreeRTOS.h"
#include "task.h"
#include "easyflash.h"

// Bouffalo Lab IoT SDK Specific Includes
#include <wifi_mgmr_ext.h>
#include <bl_wifi.h>
#include <bl_sys.h>

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

// --- Real bl_iot_sdk Diagnostic Mappings ---

static int get_upstream_rssi(void) {
    int rssi = -100;
    // Retrieves the RSSI of the currently connected upstream AP
    wifi_mgmr_rssi_get(&rssi);
    return rssi;
}

static const char* get_upstream_ip(void) {
    static char ip_str[16];
    uint32_t ip = 0;
    uint32_t gw = 0;
    uint32_t mask = 0;
    
    // Extracts actual Wi-Fi operational configurations from the manager
    wifi_mgmr_sta_ip_get(&ip, &gw, &mask);
    
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             (int)(ip & 0xFF), 
             (int)((ip >> 8) & 0xFF), 
             (int)((ip >> 16) & 0xFF), 
             (int)((ip >> 24) & 0xFF));
    return ip_str;
}

static int get_connected_client_count(void) {
    uint8_t sta_num = 0;
    // Fetches how many client stations are attached to this node's AP
    wifi_mgmr_ap_sta_cnt_get(&sta_num);
    return sta_num;
}

static uint32_t get_free_heap_size(void) {
    return xPortGetFreeHeapSize();
}

static uint32_t get_system_uptime_sec(void) {
    // Converts FreeRTOS kernel ticks to raw operational execution seconds
    return xTaskGetTickCount() / configTICK_RATE_HZ;
}

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

    char *rx_buf = pvPortMalloc(2048);
    char *body = pvPortMalloc(2048);
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

        memset(rx_buf, 0, 2048);
        int read_len = read(client_fd, rx_buf, 2047);

        if (read_len > 0) {
            rx_buf[read_len] = '\0';

            if (strstr(rx_buf, "GET /favicon.ico")) {
                const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                send(client_fd, not_found, strlen(not_found), 0);
                close(client_fd);
                continue;
            }

            bool is_stats_page = (strstr(rx_buf, "GET /stats") != NULL);

            if (strncmp(rx_buf, "POST", 4) == 0) {
                char *body_start = strstr(rx_buf, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    char val_buf[64];

                    if (get_form_field(body_start, "UpstreamSSID", val_buf, sizeof(val_buf))) {
                        ef_set_env("UpstreamSSID", val_buf);
                    }
                    if (get_form_field(body_start, "UpstreamPSK", val_buf, sizeof(val_buf))) {
                        ef_set_env("UpstreamPSK", val_buf);
                    }
                    if (get_form_field(body_start, "DeviceSSID", val_buf, sizeof(val_buf))) {
                        ef_set_env("DeviceSSID", val_buf);
                    }
                    if (get_form_field(body_start, "DevicePSK", val_buf, sizeof(val_buf))) {
                        ef_set_env("DevicePSK", val_buf);
                    }

                    bool ui_checked = get_form_field(body_start, "EnableUI", val_buf, sizeof(val_buf));
                    ef_set_env("EnableUI", ui_checked ? "1" : "0");

                    ef_save_env();
                }
            }

            int body_len = 0;

            if (is_stats_page) {
                // --- DIAGNOSTICS PAGE (/stats) ---
                body_len = snprintf(body, 2048,
                    "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"5\"></head><body>"
                    "<h2>Device Diagnostics & Live Statistics</h2>"
                    "<p><a href=\"/\">&larr; Back to Settings</a> (Auto-refreshing every 5s)</p>"
                    
                    "<h3>Upstream Connection</h3>"
                    "<table border=\"1\" cellpadding=\"5\" cellspacing=\"0\">"
                    "  <tr><td><b>Connected IP:</b></td><td>%s</td></tr>"
                    "  <tr><td><b>Signal Strength (RSSI):</b></td><td>%d dBm</td></tr>"
                    "</table>"
                    
                    "<h3>Local Access Point Status</h3>"
                    "<table border=\"1\" cellpadding=\"5\" cellspacing=\"0\">"
                    "  <tr><td><b>Active Client Connections:</b></td><td>%d devices</td></tr>"
                    "</table>"

                    "<h3>System Performance</h3>"
                    "<table border=\"1\" cellpadding=\"5\" cellspacing=\"0\">"
                    "  <tr><td><b>Free Heap Memory:</b></td><td>%u bytes</td></tr>"
                    "  <tr><td><b>System Uptime:</b></td><td>%u seconds</td></tr>"
                    "</table>"
                    "</body></html>",
                    get_upstream_ip(),
                    get_upstream_rssi(),
                    get_connected_client_count(),
                    get_free_heap_size(),
                    get_system_uptime_sec()
                );
            } else {
                // --- CONFIGURATION PAGE (/) ---
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

                body_len = snprintf(body, 2048,
                    "<!DOCTYPE html><html><body>"
                    "<h2>BL602 Wi-Fi & Device Settings</h2>"
                    "<p><a href=\"/stats\"><b>View Live Diagnostics & Stats &rarr;</b></a></p>"
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
            }

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