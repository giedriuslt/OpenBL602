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
#include "level2.h"

// Max client stations the BL602 SoftAP usually tracks internally
#define AP_MAX_STA_COUNT 7


static int get_upstream_rssi(void) {
    int rssi = -100;
    // Retrieves the RSSI of the currently connected upstream AP
    wifi_mgmr_rssi_get(&rssi);
    return rssi;
}

static const char* get_upstream_ip(void) {
    static char ip_str[16];
    uint32_t ip = 0, gw = 0, mask = 0;
    wifi_mgmr_sta_ip_get(&ip, &gw, &mask);
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
             (int)(ip & 0xFF), (int)((ip >> 8) & 0xFF), 
             (int)((ip >> 16) & 0xFF), (int)((ip >> 24) & 0xFF));
    return ip_str;
}

static int get_connected_client_count(void) {
    uint8_t sta_num = 0;
    // Fetches how many client stations are attached to this node's AP
    wifi_mgmr_ap_sta_cnt_get(&sta_num);
    return sta_num;
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
char *trim(char *str) {
    if (!str) return NULL;

    // 1. Find the first non-whitespace character
    char *start = str;
    while (isspace((unsigned char)*start)) {
        start++;
    }

    // 2. If string is empty or all whitespace
    if (*start == '\0') {
        *str = '\0';
        return str;
    }

    // 3. Find the last non-whitespace character
    char *end = start + strlen(start) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }

    // 4. Shift trimmed substring to the start of the original buffer
    size_t len = (size_t)(end - start + 1);
    memmove(str, start, len);

    // 5. Null-terminate at the new length
    str[len] = '\0';

    return str;
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
    trim(out_val);
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

    // Allocating chunk buffer for streaming HTML elements efficiently
    char *chunk = pvPortMalloc(1024);
    if (!chunk) {
        close(server_fd);
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) continue;
        printf("Accepted fd %d", client_fd);
        
        // Define a 5-second timeout structure
        struct timeval timeout;
        timeout.tv_sec = 0;       // 5 seconds
        timeout.tv_usec = 500000;      // 0 microseconds

        // Set Receive Timeout
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            printf("Failed to set SO_RCVTIMEO on fd %d", client_fd);
        }

        // Set Send Timeout (Highly recommended so a stalled client can't block send() indefinitely)
        if (setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
            printf("Failed to set SO_SNDTIMEO on fd %d", client_fd);
        }

        memset(chunk, 0, 1024);
        int total_read = 0;
        int read_len = 0;
        const int capacity = 1023; // Save 1 byte at the end for '\0'

        // Accumulate data into chunk until capacity is reached
        while (total_read == 0) {
            read_len = read(client_fd, chunk + total_read, capacity - total_read);

            if (read_len > 0) {
                total_read += read_len;
                chunk[total_read] = '\0'; // Guarantee valid string termination at all times
            } 
            else if (read_len == 0) {
                // Connection closed by peer
                printf("Client on fd %d closed connection. Read %d total bytes.\n", client_fd, total_read);
                break;
            } 
            else {
                // Error handling
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    printf("Read timeout on fd %d after %d bytes\n", client_fd, total_read);
                    break;
                } else {
                    printf("Read error on fd %d (errno: %d)\n", client_fd, errno);
                    break;
                }
            }
        }

        if (total_read > 0) {
            printf("Read len %d", total_read);
            chunk[total_read] = '\0';

            if (strstr(chunk, "GET /favicon.ico")) {
                const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                send(client_fd, not_found, strlen(not_found), 0);
                close(client_fd);
                continue;
            }

            bool is_stats_page = (strstr(chunk, "GET /stats") != NULL);

            if (strncmp(chunk, "POST", 4) == 0) {
                char *body_start = strstr(chunk, "\r\n\r\n");
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

            // Send chunked/streamed response headers
            const char *http_ok_header = 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Connection: close\r\n\r\n";
            send(client_fd, http_ok_header, strlen(http_ok_header), 0);

            if (is_stats_page) {
                // --- CHUNK 1: Header & Static Metrics ---
                int len = snprintf(chunk, 1024,
                    "<!DOCTYPE html><html><head><meta http-equiv=\"refresh\" content=\"5\"></head><body>"
                    "<h2>Device Diagnostics & Live Statistics</h2>"
                    "<p><a href=\"/\">&larr; Back to Settings</a> (Auto-refreshing every 5s)</p>"
                    "<h3>System Status</h3>"
                    "<table border=\"1\" cellpadding=\"5\" cellspacing=\"0\">"
                    "  <tr><td><b>Upstream IP:</b></td><td>%s</td></tr>"
                    "  <tr><td><b>Upstream RSSI:</b></td><td>%d dBm</td></tr>"
                    "  <tr><td><b>Total Clients:</b></td><td>%d connected</td></tr>"
                    "  <tr><td><b>Free Heap:</b></td><td>%u bytes</td></tr>"
                    "  <tr><td><b>Uptime:</b></td><td>%u sec</td></tr>"
                    "</table><br>",
                    get_upstream_ip(), get_upstream_rssi(), get_connected_client_count(),
                    (unsigned int)xPortGetFreeHeapSize(), (unsigned int)(xTaskGetTickCount() / configTICK_RATE_HZ)
                );
                send(client_fd, chunk, len, 0);

                // --- CHUNK 2: Client Index Station Table ---
                len = snprintf(chunk, 1024,
                    "<h3>Connected Station Details</h3>"
                    "<table border=\"1\" cellpadding=\"5\" cellspacing=\"0\">"
                    "  <tr bgcolor=\"#dddddd\">"
                    "    <th>Index</th><th>MAC Address</th><th>RSSI</th><th>Data Rate Index</th>"
                    "  </tr>"
                );
                send(client_fd, chunk, len, 0);

                int active_rows = 0;
                for (uint8_t i = 0; i < AP_MAX_STA_COUNT; i++) {
                    wifi_sta_basic_info_t sta;
                    memset(&sta, 0, sizeof(sta));
                    
                    if (wifi_mgmr_ap_sta_info_get((struct wifi_sta_basic_info *)&sta, i) == 0) {
                        if (sta.is_used) {
                            active_rows++;
                            len = snprintf(chunk, 1024,
                                "  <tr>"
                                "    <td>%d</td>"
                                "    <td>%02X:%02X:%02X:%02X:%02X:%02X</td>"
                                "    <td>%d dBm</td>"
                                "    <td>MCS %d</td>"
                                "  </tr>",
                                sta.sta_idx,
                                sta.sta_mac[0], sta.sta_mac[1], sta.sta_mac[2],
                                sta.sta_mac[3], sta.sta_mac[4], sta.sta_mac[5],
                                sta.rssi, sta.data_rate
                            );
                            send(client_fd, chunk, len, 0);
                        }
                    }
                }

                if (active_rows == 0) {
                    const char *no_clients = "  <tr><td colspan=\"4\" align=\"center\">No active client connections found.</td></tr>";
                    send(client_fd, no_clients, strlen(no_clients), 0);
                }

                const char *table_footer = "</table><br>";
                send(client_fd, table_footer, strlen(table_footer), 0);
                
                sprintf_lwip_stats(chunk, 1024);
                send(client_fd, chunk, strlen(chunk), 0);

                // --- CHUNK 3: Network Traffic Log ---
                const char *log_header = 
                    "<h3>Packet Traffic Log (ICMP / ARP / DHCP)</h3>"
                    "<pre style=\"background:#f4f4f4; border:1px solid #ccc; padding:10px; max-height:250px; overflow-y:scroll;\">";
                send(client_fd, log_header, strlen(log_header), 0);

                char *log_buf = pvPortMalloc(4096);
                if (log_buf) {
                    size_t log_bytes = net_log_read(log_buf, 4096);
                    if (log_bytes > 0) {
                        send(client_fd, log_buf, log_bytes, 0);
                    } else {
                        const char *empty_msg = "No traffic recorded yet.";
                        send(client_fd, empty_msg, strlen(empty_msg), 0);
                    }
                    vPortFree(log_buf);
                }

                const char *page_footer = "</pre></body></html>";
                send(client_fd, page_footer, strlen(page_footer), 0);

            } else {
                // --- CONFIGURATION PAGE (/) ---
                char up_ssid[33], up_psk[65], dev_ssid[33], dev_psk[65], enable_ui[4];
                get_env_str("UpstreamSSID", up_ssid, sizeof(up_ssid), "");
                get_env_str("UpstreamPSK", up_psk, sizeof(up_psk), "");
                get_env_str("DeviceSSID", dev_ssid, sizeof(dev_ssid), "BL602_Node");
                get_env_str("DevicePSK", dev_psk, sizeof(dev_psk), "12345678");
                get_env_str("EnableUI", enable_ui, sizeof(enable_ui), "0");

                int len = snprintf(chunk, 1024,
                    "<!DOCTYPE html><html><body>"
                    "<h2>BL602 Wi-Fi & Device Settings</h2>"
                    "<p><a href=\"/stats\"><b>View Live Diagnostics & Stats &rarr;</b></a></p>"
                    "<form action=\"/\" method=\"post\">"
                    "  <h3>Upstream Network (Client)</h3>"
                    "  <label>SSID:</label><br><input type=\"text\" name=\"UpstreamSSID\" value=\"%s\"><br>"
                    "  <label>Password:</label><br><input type=\"password\" name=\"UpstreamPSK\" value=\"%s\"><br><br>"
                    "  <h3>Local Access Point (AP)</h3>"
                    "  <label>Device SSID:</label><br><input type=\"text\" name=\"DeviceSSID\" value=\"%s\"><br>"
                    "  <label>Device Password:</label><br><input type=\"password\" name=\"DevicePSK\" value=\"%s\"><br><br>"
                    "  <input type=\"checkbox\" name=\"EnableUI\" value=\"1\" %s><label> Enable Web UI</label><br><br>"
                    "  <input type=\"submit\" value=\"Save Settings\">"
                    "</form></body></html>",
                    up_ssid, up_psk, dev_ssid, dev_psk, (strcmp(enable_ui, "1") == 0) ? "checked" : ""
                );
                send(client_fd, chunk, len, 0);
            }
        }
        else
        {
            printf("Read len zero");
        }
        close(client_fd);
    }
}

void start_webserver_task(void) {
    xTaskCreate(http_server_task, "HTTP_Server", 4096, NULL, tskIDLE_PRIORITY + 2, NULL);
}