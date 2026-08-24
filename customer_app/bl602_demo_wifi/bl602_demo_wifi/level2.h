void app_ap_init(const char *ssid, const char *key, uint8_t channel);
void app_sta_init(const char *ssid, const char *key);
void app_recovery_init(uint8_t channel);
size_t net_log_read(char *dst, size_t max_len);
int sprintf_lwip_stats(char *buf, size_t max_len);
void refresh_nat_entries(void);