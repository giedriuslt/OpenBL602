/*
 * Copyright (c) 2016-2022 Bouffalolab.
 *
 * This file is part of
 *     *** Bouffalolab Software Dev Kit ***
 *      (see www.bouffalolab.com).
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright notice,
 *      this list of conditions and the following disclaimer in the documentation
 *      and/or other materials provided with the distribution.
 *   3. Neither the name of Bouffalo Lab nor the names of its contributors
 *      may be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <FreeRTOS.h>
#include <task.h>
#include <timers.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <vfs.h>
#include <aos/kernel.h>
#include <aos/yloop.h>
#include <event_device.h>
#include <cli.h>

#include <lwip/tcpip.h>
#include <lwip/sockets.h>
#include <lwip/netdb.h>
#include <lwip/tcp.h>
#include <lwip/err.h>
#include <http_client.h>
#include <netutils/netutils.h>

#include <bl602_glb.h>
#include <bl602_hbn.h>

#include <bl_uart.h>
#include <bl_chip.h>
#include <bl_wifi.h>
#include <hal_wifi.h>
#include <bl_sec.h>
#include <bl_cks.h>
#include <bl_irq.h>
#include <bl_dma.h>
#include <bl_timer.h>
#include <bl_gpio_cli.h>
#include <bl_wdt.h>
#include <bl_wdt_cli.h>
#include <hosal_uart.h>
#include <hosal_adc.h>
#include <hal_sys.h>
#include <hal_gpio.h>
#include <hal_boot2.h>
#include <hal_board.h>
#include <looprt.h>
#include <loopset.h>
#include <sntp.h>
#include <bl_sys_time.h>
#include <bl_sys.h>
#include <bl_sys_ota.h>
#include <bl_romfs.h>
#include <fdt.h>
#include <device/vfs_uart.h>
#include <easyflash.h>
#include <bl60x_fw_api.h>
#include <wifi_mgmr_ext.h>
#include <utils_log.h>
#include <libfdt.h>
#include <blog.h>
#include <bl_wps.h>
#include "level2.h"
#include "config_srv.h"

#define mainHELLO_TASK_PRIORITY     ( 20 )
#define UART_ID_2 (2)
#define WIFI_AP_PSM_INFO_SSID           "conf_ap_ssid"
#define WIFI_AP_PSM_INFO_PASSWORD       "conf_ap_psk"
#define WIFI_AP_PSM_INFO_PMK            "conf_ap_pmk"
#define WIFI_AP_PSM_INFO_BSSID          "conf_ap_bssid"
#define WIFI_AP_PSM_INFO_CHANNEL        "conf_ap_channel"
#define WIFI_AP_PSM_INFO_IP             "conf_ap_ip"
#define WIFI_AP_PSM_INFO_MASK           "conf_ap_mask"
#define WIFI_AP_PSM_INFO_GW             "conf_ap_gw"
#define WIFI_AP_PSM_INFO_DNS1           "conf_ap_dns1"
#define WIFI_AP_PSM_INFO_DNS2           "conf_ap_dns2"
#define WIFI_AP_PSM_INFO_IP_LEASE_TIME  "conf_ap_ip_lease_time"
#define WIFI_AP_PSM_INFO_GW_MAC         "conf_ap_gw_mac"
#define CLI_CMD_AUTOSTART1              "cmd_auto1"
#define CLI_CMD_AUTOSTART2              "cmd_auto2"

/* TODO: const */
volatile uint32_t uxTopUsedPriority __attribute__((used)) =  configMAX_PRIORITIES - 1;

static wifi_conf_t conf =
{
    .country_code = "CN",
};

static wifi_interface_t wifi_interface;

static void event_cb_wifi_event(input_event_t *event, void *private_data)
{
    static char *ssid;
    static char *password;
    struct sm_connect_tlv_desc* ele = NULL;

    switch (event->code) {
        case CODE_WIFI_ON_INIT_DONE:
        {
            printf("[APP] [EVT] INIT DONE %lld\r\n", aos_now_ms());
            wifi_mgmr_start_background(&conf);
        }
        break;
        case CODE_WIFI_ON_MGMR_DONE:
        {
            printf("[APP] [EVT] MGMR DONE %lld, now %lums\r\n", aos_now_ms(), bl_timer_now_us()/1000);
        }
        break;
        case CODE_WIFI_ON_MGMR_DENOISE:
        {
            printf("[APP] [EVT] Microwave Denoise is ON %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_SCAN_DONE:
        {
            printf("[APP] [EVT] SCAN Done %lld\r\n", aos_now_ms());
            wifi_mgmr_cli_scanlist();
        }
        break;
        case CODE_WIFI_ON_SCAN_DONE_ONJOIN:
        {
            printf("[APP] [EVT] SCAN On Join %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_DISCONNECT:
        {
            printf("[APP] [EVT] disconnect %lld, Reason: %s\r\n",
                aos_now_ms(),
                wifi_mgmr_status_code_str(event->value)
            );
#if 1
            /* Get every ele in diagnose tlv data */
            while ((ele = wifi_mgmr_diagnose_tlv_get_ele()))
            {
                printf("[APP] [EVT] diagnose tlv data %lld, id: %d, len: %d, data: %p\r\n", aos_now_ms(), 
                    ele->id, ele->len, ele->data);

                /* MUST free diagnose tlv data ele */
                wifi_mgmr_diagnose_tlv_free_ele(ele);
            }

            printf("[SYS] Memory left is %d Bytes\r\n", xPortGetFreeHeapSize());
#endif
        }
        break;
        case CODE_WIFI_ON_CONNECTING:
        {
            printf("[APP] [EVT] Connecting %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_CMD_RECONNECT:
        {
            printf("[APP] [EVT] Reconnect %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_CONNECTED:
        {
#if 1
            /* Get every ele in diagnose tlv data */
            while ((ele = wifi_mgmr_diagnose_tlv_get_ele()))
            {
                printf("[APP] [EVT] diagnose tlv data %lld, id: %d, len: %d, data: %p\r\n", aos_now_ms(), 
                    ele->id, ele->len, ele->data);

                /* MUST free diagnose tlv data */
                wifi_mgmr_diagnose_tlv_free_ele(ele);
            }

            printf("[SYS] Memory left is %d Bytes\r\n", xPortGetFreeHeapSize());
#endif
            printf("[APP] [EVT] connected %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_PRE_GOT_IP:
        {
            printf("[APP] [EVT] connected %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_GOT_IP:
        {
            printf("[APP] [EVT] GOT IP %lld\r\n", aos_now_ms());
            printf("[SYS] Memory left is %d Bytes\r\n", xPortGetFreeHeapSize());
        }
        break;
        case CODE_WIFI_ON_EMERGENCY_MAC:
        {
            printf("[APP] [EVT] EMERGENCY MAC %lld\r\n", aos_now_ms());
            hal_reboot();//one way of handling emergency is reboot. Maybe we should also consider solutions
        }
        break;
        case CODE_WIFI_ON_PROV_SSID:
        {
            printf("[APP] [EVT] [PROV] [SSID] %lld: %s\r\n",
                    aos_now_ms(),
                    event->value ? (const char*)event->value : "UNKNOWN"
            );
            if (ssid) {
                vPortFree(ssid);
                ssid = NULL;
            }
            ssid = (char*)event->value;
        }
        break;
        case CODE_WIFI_ON_PROV_BSSID:
        {
            printf("[APP] [EVT] [PROV] [BSSID] %lld: %s\r\n",
                    aos_now_ms(),
                    event->value ? (const char*)event->value : "UNKNOWN"
            );
            if (event->value) {
                vPortFree((void*)event->value);
            }
        }
        break;
        case CODE_WIFI_ON_PROV_PASSWD:
        {
            printf("[APP] [EVT] [PROV] [PASSWD] %lld: %s\r\n", aos_now_ms(),
                    event->value ? (const char*)event->value : "UNKNOWN"
            );
            if (password) {
                vPortFree(password);
                password = NULL;
            }
            password = (char*)event->value;
        }
        break;
        case CODE_WIFI_ON_PROV_CONNECT:
        {
            printf("[APP] [EVT] [PROV] [CONNECT] %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_PROV_DISCONNECT:
        {
            printf("[APP] [EVT] [PROV] [DISCONNECT] %lld\r\n", aos_now_ms());
        }
        break;
        case CODE_WIFI_ON_AP_STA_ADD:
        {
            printf("[APP] [EVT] [AP] [ADD] %lld, sta idx is %lu\r\n", aos_now_ms(), (uint32_t)event->value);
        }
        break;
        case CODE_WIFI_ON_AP_STA_DEL:
        {
            uint8_t sta_idx = (uint8_t)(uint32_t)event->value;
            printf("[APP] [EVT] [AP] [DEL] %lld, sta idx is %u\r\n", aos_now_ms(), sta_idx);

            refresh_nat_entries();
            break;
        }
        break;
        default:
        {
            printf("[APP] [EVT] Unknown code %u, %lld\r\n", event->code, aos_now_ms());
            /*nothing*/
        }
    }
}



static void cmd_stack_wifi(char *buf, int len, int argc, char **argv)
{
    /*wifi fw stack and thread stuff*/
    static uint8_t stack_wifi_init  = 0;


    if (1 == stack_wifi_init) {
        puts("Wi-Fi Stack Started already!!!\r\n");
        return;
    }
    stack_wifi_init = 1;

    printf("Start Wi-Fi fw @%lums\r\n", bl_timer_now_us()/1000);
    hal_wifi_start_firmware_task();
    /*Trigger to start Wi-Fi*/
    printf("Start Wi-Fi fw is Done @%lums\r\n", bl_timer_now_us()/1000);
    aos_post_event(EV_WIFI, CODE_WIFI_ON_INIT_DONE, 0);

}


static void _cli_init()
{
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


static void watchdog_task(void *pvParameters) {
    // 1. Retrieve current boot counter from EasyFlash env
    char boot_str[16];
    get_env_str("boot_count", boot_str, sizeof(boot_str), "0");
    int boot_count = atoi(boot_str) + 1;

    snprintf(boot_str, sizeof(boot_str), "%d", boot_count);
    ef_set_env("boot_count", boot_str);

    ef_save_env();

    // 3. Configure hardware watchdog timer for 4096 ms
    bl_wdt_init(4096);

    uint32_t uptime_sec = 0;
    bool reset_done = false;

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        uptime_sec++;
        
        // Feed the hardware watchdog timer
        bl_wdt_feed();

        // 4. Reset boot counter to zero after 10 seconds of stable boot
        if (!reset_done && uptime_sec >= 10) {
            ef_set_env("boot_count", "0");
            ef_save_env();
            reset_done = true;
        }
    }
}

void start_watchdog_task(void) {
    // Priority lower than HTTP_Server (tskIDLE_PRIORITY + 1)
    // CPU-bound infinite loops in HTTP thread will starve this task and trigger WDT reset
    xTaskCreate(watchdog_task, "WDT_Task", 1024, NULL, tskIDLE_PRIORITY + 1, NULL);
}

static bool is_wifi_param_valid(const char *ssid, const char *key) {
    if (ssid == NULL || strlen(ssid) == 0) {
        return false;
    }
    if (key == NULL || strlen(key) < 8) {
        return false;
    }
    return true;
}

void app_mac_nat_init_from_env(void)
{
    vTaskDelay(pdMS_TO_TICKS(1000));

    char boot_str[16] = {0};
    char sta_ssid[33] = {0};
    char sta_key[65]  = {0};
    char ap_ssid[33]  = {0};
    char ap_key[65]   = {0};

    // 1. Read EasyFlash keys matching your form fields
    get_env_str("boot_count",   boot_str, sizeof(boot_str), "0");
    get_env_str("UpstreamSSID", sta_ssid, sizeof(sta_ssid), "");
    get_env_str("UpstreamPSK",  sta_key,  sizeof(sta_key),  "");
    get_env_str("DeviceSSID",   ap_ssid,  sizeof(ap_ssid),  "");
    get_env_str("DevicePSK",    ap_key,   sizeof(ap_key),   "");

    int boot_count = atoi(boot_str);
    uint8_t ap_channel = (uint8_t)6;
    if (ap_channel < 1 || ap_channel > 14) {
        ap_channel = 6;
    }

    // 2. Validate both STA and AP configurations
    bool sta_ok = is_wifi_param_valid(sta_ssid, sta_key);
    bool ap_ok  = is_wifi_param_valid(ap_ssid, ap_key);

    // 3. Fallback to recovery mode if boot limit reached or validation fails
    if (boot_count >= 5) {
        printf("[RECOVERY] Boot count (%d) >= 5! Entering Recovery Mode...\r\n", boot_count);
        app_recovery_init(ap_channel);
        return;
    }

    if (!sta_ok || !ap_ok) {
        printf("[RECOVERY] Credential validation failed (Upstream OK: %d, Device OK: %d). Entering Recovery Mode...\r\n", 
               sta_ok, ap_ok);
        app_recovery_init(ap_channel);
        return;
    }

    // 4. Start concurrent AP + STA if credentials pass
    printf("[MAC_NAT] Verified environment variables. Starting AP+STA mode on channel %d...\r\n", ap_channel);
    app_sta_init(sta_ssid, sta_key);
    app_ap_init(ap_ssid, ap_key, ap_channel);
}

static void proc_main_entry(void *pvParameters)
{
    easyflash_init();
    _cli_init();

    aos_register_event_filter(EV_WIFI, event_cb_wifi_event, NULL);
    cmd_stack_wifi(NULL, 0, 0, NULL);
    start_watchdog_task();
    app_mac_nat_init_from_env();
    start_webserver_task();

    vTaskDelete(NULL);
}

static void system_thread_init()
{
    /*nothing here*/
}

void main()
{
    bl_sys_init();
    system_thread_init();

    xTaskCreate(proc_main_entry, (char*)"main_entry", 1024, NULL, 15, NULL);
    puts("[OS] Starting TCP/IP Stack...\r\n");
    tcpip_init(NULL, NULL);
}
