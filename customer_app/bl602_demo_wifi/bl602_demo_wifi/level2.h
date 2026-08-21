void app_mac_nat_init(const char *upstream_ssid, const char *upstream_key,
                      const char *softap_ssid,   const char *softap_key);
size_t net_log_read(char *dst, size_t max_len);
int sprintf_lwip_stats(char *buf, size_t max_len);
void remove_nat_entry_by_mac(const uint8_t *mac);