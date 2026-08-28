#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <wifi_mgmr_ext.h>
#include <FreeRTOS.h>
#include <task.h>
#include "easyflash.h"
#include "semphr.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/etharp.h"
#include "lwip/prot/ip4.h"
#include "lwip/opt.h"
#include "lwip/stats.h"

#define MAX_NAT_ENTRIES 16

#ifndef SIZEOF_IPH
#define SIZEOF_IPH sizeof(struct ip_hdr)
#endif

#ifndef IP_PROTO_ICMP
#define IP_PROTO_ICMP 1
#endif

// Max client stations the BL602 SoftAP usually tracks internally
#define AP_MAX_STA_COUNT 7

static struct netif *g_ap_netif  = NULL;
static struct netif *g_sta_netif = NULL;

#define NET_LOG_BUF_SIZE 4096

static char g_net_log_buf[NET_LOG_BUF_SIZE];
static size_t g_log_head = 0;
static size_t g_log_count = 0;
static SemaphoreHandle_t g_log_mutex = NULL;

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

static void net_log_init_mutex(void) {
    if (!g_log_mutex) {
        g_log_mutex = xSemaphoreCreateMutex();
    }
}

// Write string to static rolling ring buffer
static void net_log_write(const char *str) {
    net_log_init_mutex();
    if (xSemaphoreTake(g_log_mutex, pdMS_TO_TICKS(10)) != pdTRUE) return;

    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        g_net_log_buf[g_log_head] = str[i];
        g_log_head = (g_log_head + 1) % NET_LOG_BUF_SIZE;
        if (g_log_count < NET_LOG_BUF_SIZE) {
            g_log_count++;
        }
    }
    xSemaphoreGive(g_log_mutex);
}

// Copy the rolling buffer sequentially into a target destination buffer
size_t net_log_read(char *dst, size_t max_len) {
    if (!dst || max_len == 0) return 0;
    net_log_init_mutex();

    if (xSemaphoreTake(g_log_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        dst[0] = '\0';
        return 0;
    }

    size_t copy_len = (g_log_count < max_len - 1) ? g_log_count : max_len - 1;
    size_t start = (g_log_head + NET_LOG_BUF_SIZE - g_log_count) % NET_LOG_BUF_SIZE;

    for (size_t i = 0; i < copy_len; i++) {
        dst[i] = g_net_log_buf[(start + i) % NET_LOG_BUF_SIZE];
    }
    dst[copy_len] = '\0';

    xSemaphoreGive(g_log_mutex);
    return copy_len;
}

// Parse raw L2 Ethernet frame and log ICMP, ARP, DHCP, and HTTP GET packets
void net_log_packet(bool is_tx, const uint8_t *frame, uint16_t len) {
    if (!frame || len < 14) return;

    uint16_t eth_type = (frame[12] << 8) | frame[13];
    uint16_t ip_offset = 14;

    // Handle 802.1Q VLAN Tagging
    if (eth_type == 0x8100 && len >= 18) {
        eth_type = (frame[16] << 8) | frame[17];
        ip_offset = 18;
    }

    uint32_t sec = xTaskGetTickCount() / configTICK_RATE_HZ;
    char log_entry[128];

    // ARP Packets
    if (eth_type == 0x0806 && len >= (ip_offset + 28)) {
        uint16_t op = (frame[ip_offset + 6] << 8) | frame[ip_offset + 7];
        snprintf(log_entry, sizeof(log_entry),
                 "[%us][%s][ARP] %s %d.%d.%d.%d -> %d.%d.%d.%d\n",
                 (unsigned int)sec, is_tx ? "TX" : "RX",
                 (op == 1) ? "REQ" : "REP",
                 frame[ip_offset + 14], frame[ip_offset + 15], frame[ip_offset + 16], frame[ip_offset + 17],
                 frame[ip_offset + 24], frame[ip_offset + 25], frame[ip_offset + 26], frame[ip_offset + 27]);
        net_log_write(log_entry);
    }
    // IPv4 Packets
    else if (eth_type == 0x0800 && len >= (ip_offset + 20)) {
        uint8_t ihl = (frame[ip_offset] & 0x0F) * 4;
        uint8_t proto = frame[ip_offset + 9];
        uint16_t l4_offset = ip_offset + ihl;

        // ICMP (Protocol 1)
        if (proto == 1 && len >= (l4_offset + 8)) {
            uint8_t type = frame[l4_offset];
            snprintf(log_entry, sizeof(log_entry),
                     "[%us][%s][ICMP] Type:%d %d.%d.%d.%d -> %d.%d.%d.%d\n",
                     (unsigned int)sec, is_tx ? "TX" : "RX", type,
                     frame[ip_offset + 12], frame[ip_offset + 13], frame[ip_offset + 14], frame[ip_offset + 15],
                     frame[ip_offset + 16], frame[ip_offset + 17], frame[ip_offset + 18], frame[ip_offset + 19]);
            net_log_write(log_entry);
        }
        // TCP / HTTP GET (Protocol 6)
		else if (proto == 6 && len >= (l4_offset + 20)) {
			uint8_t tcp_hdr_len = ((frame[l4_offset + 12] >> 4) & 0x0F) * 4;
			uint16_t payload_offset = l4_offset + tcp_hdr_len;
			
			uint16_t src_port = (frame[l4_offset] << 8) | frame[l4_offset + 1];
			uint16_t dst_port = (frame[l4_offset + 2] << 8) | frame[l4_offset + 3];

			// Check if packet contains "GET " payload
			bool is_get = (len >= payload_offset + 4) && 
						  (memcmp(&frame[payload_offset], "GET ", 4) == 0);

			snprintf(log_entry, sizeof(log_entry),
					 "[%us][%s][%s] %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u (payload: %d bytes)\n",
					 (unsigned int)sec, is_tx ? "TX" : "RX",
					 is_get ? "HTTP GET" : "TCP",
					 frame[ip_offset + 12], frame[ip_offset + 13], frame[ip_offset + 14], frame[ip_offset + 15], src_port,
					 frame[ip_offset + 16], frame[ip_offset + 17], frame[ip_offset + 18], frame[ip_offset + 19], dst_port,
					 (len > payload_offset) ? (len - payload_offset) : 0);
			
			net_log_write(log_entry);
		}
        // UDP / DHCP (Protocol 17)
        else if (proto == 17 && len >= (l4_offset + 8)) {
            uint16_t src_port = (frame[l4_offset] << 8) | frame[l4_offset + 1];
            uint16_t dst_port = (frame[l4_offset + 2] << 8) | frame[l4_offset + 3];

            if ((src_port == 67 || src_port == 68) && (dst_port == 67 || dst_port == 68)) {
                snprintf(log_entry, sizeof(log_entry),
                         "[%us][%s][DHCP] Port %d->%d\n",
                         (unsigned int)sec, is_tx ? "TX" : "RX", src_port, dst_port);
                net_log_write(log_entry);
            }
        }
    }
}



int sprintf_lwip_stats(char *buf, size_t max_len) {
#if LWIP_STATS
    int offset = 0;

    // Format Active Socket and PCB Counts
#if MEMP_STATS
    offset += snprintf(buf + offset, max_len - offset,
		"<h3> lwip stats</h3>"
		"<pre>"
        "--- Active Sockets & PCBs ---\n"
        "Sockets/Netconns: %d (Max: %d)\n"
        "TCP Active:       %d (Max: %d)\n"
        "TCP Listen:       %d (Max: %d)\n"
        "UDP PCBs:         %d (Max: %d)\n\n",
        (int)lwip_stats.memp[MEMP_NETCONN]->used, 
        (int)lwip_stats.memp[MEMP_NETCONN]->max,
        (int)lwip_stats.memp[MEMP_TCP_PCB]->used, 
        (int)lwip_stats.memp[MEMP_TCP_PCB]->max,
        (int)lwip_stats.memp[MEMP_TCP_PCB_LISTEN]->used, 
        (int)lwip_stats.memp[MEMP_TCP_PCB_LISTEN]->max,
        (int)lwip_stats.memp[MEMP_UDP_PCB]->used, 
        (int)lwip_stats.memp[MEMP_UDP_PCB]->max);
#endif

    // Format Heap Memory Stats
    offset += snprintf(buf + offset, max_len - offset,
        "--- Heap Mem ---\nAvail: %d | Used: %d | Max: %d | Err: %d\n\n",
        (int)lwip_stats.mem.avail, (int)lwip_stats.mem.used,
        (int)lwip_stats.mem.max, (int)lwip_stats.mem.err);

    // Format Link Layer Stats
    offset += snprintf(buf + offset, max_len - offset,
        "--- Link Layer ---\nRx: %d | Tx: %d | Drop: %d | ChkErr: %d\n\n",
        (int)lwip_stats.link.recv, (int)lwip_stats.link.xmit,
        (int)lwip_stats.link.drop, (int)lwip_stats.link.chkerr);

    // Format IP Layer Stats
    offset += snprintf(buf + offset, max_len - offset,
        "--- IP Layer ---\nRx: %d | Tx: %d | Drop: %d | ProtocolErr: %d\n</pre>",
        (int)lwip_stats.ip.recv, (int)lwip_stats.ip.xmit,
        (int)lwip_stats.ip.drop, (int)lwip_stats.ip.proterr);

    return offset; // Total bytes written into buffer
#else
    return snprintf(buf, max_len, "LWIP_STATS is disabled in lwipopts.h\n");
#endif
}

void dump_all_netifs(void) {
    struct netif *curr;

    printf("\n=== Dumping Registered lwIP Interfaces ===\r\n");
    if (netif_list == NULL) {
        printf("No netif interfaces registered yet!\r\n");
        return;
    }

    for (curr = netif_list; curr != NULL; curr = curr->next) {
        printf("Interface: %c%c%d\r\n", curr->name[0], curr->name[1], curr->num);
        printf("  - Address: %p\r\n", (void *)curr);
        printf("  - Flags  : 0x%02X (Up: %s, Link Up: %s)\r\n",
               curr->flags,
               netif_is_up(curr) ? "YES" : "NO",
               netif_is_link_up(curr) ? "YES" : "NO");
        printf("  - IP     : %s\r\n", ipaddr_ntoa(&curr->ip_addr));
    }
    printf("=========================================\n\r\n");
}

// Mapping table entry for tracking client MACs behind the BL602
typedef struct {
    uint32_t ip;         // Network byte order IPv4 address
    uint8_t  mac[6];     // Actual hardware MAC address of downstream client
    uint32_t last_seen;  // Timestamp for entry aging
} nat_entry_t;

static nat_entry_t g_nat_table[MAX_NAT_ENTRIES];
static netif_linkoutput_fn original_sta_linkoutput = NULL;
static netif_input_fn      original_sta_input      = NULL;

static netif_linkoutput_fn original_ap_linkoutput  = NULL;
static netif_input_fn      original_ap_input       = NULL;

// Helper: Check if Ethernet MAC is Multicast or Broadcast
static inline int is_mcast_or_bcast_mac(const uint8_t *mac) {
    return (mac[0] & 0x01) != 0;
}


static void log_arp_packet(const char *dir, struct pbuf *p) {
    if (!p || p->len < SIZEOF_ETH_HDR + sizeof(struct etharp_hdr)) return;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    if (lwip_ntohs(eth->type) != ETHTYPE_ARP) return;

    struct etharp_hdr *arp = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
    uint16_t opcode = lwip_ntohs(arp->opcode);

    uint32_t sip, dip;
    memcpy(&sip, &arp->sipaddr, sizeof(sip));
    memcpy(&dip, &arp->dipaddr, sizeof(dip));

    char sip_str[16], dip_str[16];
    ip4addr_ntoa_r((const ip4_addr_t *)&sip, sip_str, sizeof(sip_str));
    ip4addr_ntoa_r((const ip4_addr_t *)&dip, dip_str, sizeof(dip_str));

    const char *op_str = (opcode == ARP_REQUEST) ? "REQUEST" :
                         (opcode == ARP_REPLY)   ? "REPLY"   : "UNKNOWN";

    printf("[%s ARP %s]\r\n", dir, op_str);
    printf("  L2 Frame : %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\r\n",
           eth->src.addr[0], eth->src.addr[1], eth->src.addr[2],
           eth->src.addr[3], eth->src.addr[4], eth->src.addr[5],
           eth->dest.addr[0], eth->dest.addr[1], eth->dest.addr[2],
           eth->dest.addr[3], eth->dest.addr[4], eth->dest.addr[5]);
    printf("  ARP Body : %s (%02X:%02X:%02X:%02X:%02X:%02X) -> %s (%02X:%02X:%02X:%02X:%02X:%02X)\r\n",
           sip_str,
           arp->shwaddr.addr[0], arp->shwaddr.addr[1], arp->shwaddr.addr[2],
           arp->shwaddr.addr[3], arp->shwaddr.addr[4], arp->shwaddr.addr[5],
           dip_str,
           arp->dhwaddr.addr[0], arp->dhwaddr.addr[1], arp->dhwaddr.addr[2],
           arp->dhwaddr.addr[3], arp->dhwaddr.addr[4], arp->dhwaddr.addr[5]);
}


static void log_icmp_packet(const char *dir, struct pbuf *p) {
    if (p->len < SIZEOF_ETH_HDR + SIZEOF_IPH) return;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    if (lwip_ntohs(eth->type) != ETHTYPE_IP) return;

    struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
    
    if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
        uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
        struct icmp_echo_hdr *icmp = (struct icmp_echo_hdr *)((uint8_t *)iphdr + ip_hdr_len);

        char src_str[16], dst_str[16];
        ip4addr_ntoa_r((const ip4_addr_t *)&iphdr->src, src_str, sizeof(src_str));
        ip4addr_ntoa_r((const ip4_addr_t *)&iphdr->dest, dst_str, sizeof(dst_str));

        const char *type_str = (icmp->type == ICMP_ECHO) ? "ECHO_REQ" :
                               (icmp->type == ICMP_ER)   ? "ECHO_REPLY" : "OTHER";

        printf("[%s ICMP] %s | %s -> %s | ID: %d | Seq: %d\r\n",
               dir, type_str, src_str, dst_str,
               lwip_ntohs(icmp->id), lwip_ntohs(icmp->seqno));
    }
}

static void log_dhcp_packet(const char *dir, struct pbuf *p) {
    if (!p || p->len < SIZEOF_ETH_HDR + SIZEOF_IPH + sizeof(struct udp_hdr) + 240) return;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    if (lwip_ntohs(eth->type) != ETHTYPE_IP) return;

    struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
    if (IPH_PROTO(iphdr) != 17) return; // Not UDP

    uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
    struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)iphdr + ip_hdr_len);
    uint16_t src_port = lwip_ntohs(udphdr->src);
    uint16_t dst_port = lwip_ntohs(udphdr->dest);

    // Filter for DHCP Server (67) or DHCP Client (68)
    if (src_port != 67 && src_port != 68 && dst_port != 67 && dst_port != 68) return;

    uint8_t *dhcp = (uint8_t *)udphdr + sizeof(struct udp_hdr);

    uint8_t op = dhcp[0];
    
    uint32_t xid; 
    memcpy(&xid, dhcp + 4, 4); 
    xid = lwip_ntohl(xid);
    
    uint16_t flags; 
    memcpy(&flags, dhcp + 10, 2); 
    flags = lwip_ntohs(flags);

    char ciaddr[16], yiaddr[16], siaddr[16], giaddr[16];
    ip4addr_ntoa_r((const ip4_addr_t *)(dhcp + 12), ciaddr, sizeof(ciaddr));
    ip4addr_ntoa_r((const ip4_addr_t *)(dhcp + 16), yiaddr, sizeof(yiaddr));
    ip4addr_ntoa_r((const ip4_addr_t *)(dhcp + 20), siaddr, sizeof(siaddr));
    ip4addr_ntoa_r((const ip4_addr_t *)(dhcp + 24), giaddr, sizeof(giaddr));

    uint8_t *chaddr = dhcp + 28;

    // Parse DHCP Option 53 (Message Type)
    const char *msg_type_str = "UNKNOWN";
    uint16_t dhcp_len = p->len - (SIZEOF_ETH_HDR + ip_hdr_len + sizeof(struct udp_hdr));
    if (dhcp_len >= 240) { // Magic cookie offset
        uint8_t *options = dhcp + 240;
        uint16_t opt_len = dhcp_len - 240;
        uint16_t i = 0;
        while (i < opt_len) {
            if (options[i] == 255) break; // END Option
            if (options[i] == 0) { i++; continue; } // PAD Option
            if (i + 1 >= opt_len) break;
            
            uint8_t code = options[i];
            uint8_t len = options[i+1];
            if (i + 2 + len > opt_len) break;

            if (code == 53 && len == 1) {
                switch (options[i+2]) {
                    case 1: msg_type_str = "DISCOVER"; break;
                    case 2: msg_type_str = "OFFER"; break;
                    case 3: msg_type_str = "REQUEST"; break;
                    case 4: msg_type_str = "DECLINE"; break;
                    case 5: msg_type_str = "ACK"; break;
                    case 6: msg_type_str = "NAK"; break;
                    case 7: msg_type_str = "RELEASE"; break;
                    case 8: msg_type_str = "INFORM"; break;
                }
            }
            i += 2 + len;
        }
    }

    char src_ip[16], dst_ip[16];
    ip4addr_ntoa_r((const ip4_addr_t *)&iphdr->src, src_ip, sizeof(src_ip));
    ip4addr_ntoa_r((const ip4_addr_t *)&iphdr->dest, dst_ip, sizeof(dst_ip));

    printf("\n========== FULL DHCP PACKET DUMP ==========\r\n");
    printf("Direction : %s\r\n", dir);
    printf("Type      : %s (Op: %d)\r\n", msg_type_str, op);
    printf("L2 MACs   : %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\r\n",
           eth->src.addr[0], eth->src.addr[1], eth->src.addr[2], eth->src.addr[3], eth->src.addr[4], eth->src.addr[5],
           eth->dest.addr[0], eth->dest.addr[1], eth->dest.addr[2], eth->dest.addr[3], eth->dest.addr[4], eth->dest.addr[5]);
    printf("L3 IPs    : %s:%d -> %s:%d\r\n", src_ip, src_port, dst_ip, dst_port);
    printf("Flags     : 0x%04X (Broadcast requested: %s)\r\n", flags, (flags & 0x8000) ? "YES" : "NO");
    printf("XID       : 0x%08X\r\n", (unsigned int)xid);
    printf("ciaddr    : %s\r\n", ciaddr);
    printf("yiaddr    : %s\r\n", yiaddr);
    printf("siaddr    : %s\r\n", siaddr);
    printf("giaddr    : %s\r\n", giaddr);
    printf("chaddr    : %02X:%02X:%02X:%02X:%02X:%02X\r\n", 
           chaddr[0], chaddr[1], chaddr[2], chaddr[3], chaddr[4], chaddr[5]);
    printf("===========================================\r\n");
}


static void print_nat_table(void) {
    printf("\r\n=== NAT Table Contents ===\r\n");
    printf("Slot | IP Address       | MAC Address       | Last Seen\r\n");
    printf("-----+------------------+-------------------+-----------\r\n");

    uint8_t active_count = 0;

    for (int i = 0; i < MAX_NAT_ENTRIES; i++) {
        // Skip empty entries (ip == 0)
        if (g_nat_table[i].ip == 0) {
            continue;
        }

        // Extract IP bytes directly (handles network byte order portably)
        uint8_t *ip = (uint8_t *)&g_nat_table[i].ip;
        const uint8_t *mac = g_nat_table[i].mac;

        printf("[%02d] | %-3u.%-3u.%-3u.%-3u | %02X:%02X:%02X:%02X:%02X:%02X | %u\r\n",
               i,
               ip[0], ip[1], ip[2], ip[3],
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
               g_nat_table[i].last_seen);

        active_count++;
    }

    if (active_count == 0) {
        printf(" (Table is empty)\r\n");
    }

    printf("===========================\r\n");
    printf("Active Entries: %u / %d\r\n\r\n", active_count, MAX_NAT_ENTRIES);
}

// Helper: Update or insert a MAC-to-IP mapping
static void update_nat_table(uint32_t ip, const uint8_t *mac) {
    if (ip == 0) return;
    if ((g_sta_netif && ip == netif_ip4_addr(g_sta_netif)->addr) ||
        (g_ap_netif && ip == netif_ip4_addr(g_ap_netif)->addr)) return;

    uint32_t now = xTaskGetTickCount();
    int oldest_idx = 0;
    uint32_t oldest_time = 0xFFFFFFFF;

    for (int i = 0; i < MAX_NAT_ENTRIES; i++) {
        // Match existing entry
        if (g_nat_table[i].ip == ip) {
            memcpy(g_nat_table[i].mac, mac, 6);
            g_nat_table[i].last_seen = now;
            return;
        }
        // Match empty slot
        if (g_nat_table[i].ip == 0) {
            g_nat_table[i].ip = ip;
            memcpy(g_nat_table[i].mac, mac, 6);
            g_nat_table[i].last_seen = now;
			print_nat_table();
            return;
        }
        // Track oldest entry for eviction if full
        if (g_nat_table[i].last_seen < oldest_time) {
            oldest_time = g_nat_table[i].last_seen;
            oldest_idx = i;
        }
    }

    // Table is full: Evict oldest entry
    g_nat_table[oldest_idx].ip = ip;
    memcpy(g_nat_table[oldest_idx].mac, mac, 6);
    g_nat_table[oldest_idx].last_seen = now;
}

void refresh_nat_entries(void) {
    uint8_t active_macs[AP_MAX_STA_COUNT][6];
    uint8_t active_count = 0;

    // 1. Gather MAC addresses of all currently connected STAs
    for (uint8_t i = 0; i < AP_MAX_STA_COUNT; i++) {
        wifi_sta_basic_info_t sta;
        memset(&sta, 0, sizeof(sta));

        if (wifi_mgmr_ap_sta_info_get((struct wifi_sta_basic_info *)&sta, i) == 0) {
            memcpy(active_macs[active_count], sta.sta_mac, 6);
            active_count++;
        }
    }

    // 2. Clear NAT entries whose MAC address is no longer in the active list
    for (int i = 0; i < MAX_NAT_ENTRIES; i++) {
        if (g_nat_table[i].ip == 0) {
            continue; // Skip inactive/empty slots
        }

        bool is_active = false;
        for (uint8_t j = 0; j < active_count; j++) {
            if (memcmp(g_nat_table[i].mac, active_macs[j], 6) == 0) {
                is_active = true;
                break;
            }
        }

        if (!is_active) {
            printf("[APP] [NAT] Purging stale entry for MAC: %02X:%02X:%02X:%02X:%02X:%02X\r\n",
                   g_nat_table[i].mac[0], g_nat_table[i].mac[1], g_nat_table[i].mac[2],
                   g_nat_table[i].mac[3], g_nat_table[i].mac[4], g_nat_table[i].mac[5]);
            
            memset(&g_nat_table[i], 0, sizeof(nat_entry_t));
        }
    }
	print_nat_table();
}

int lookup_nat_table_by_mac(const uint8_t *mac) {
    if (mac == NULL) return 0;

    for (int i = 0; i < MAX_NAT_ENTRIES; i++) {
        // Skip unused slots
        if (g_nat_table[i].ip == 0) {
            continue;
        }

        // Compare 6-byte MAC address
        if (memcmp(g_nat_table[i].mac, mac, 6) == 0) {
            // Zero out the slot to mark it as empty for future updates
            return 1;
        }
    }
	return 0;
}

// Helper: Lookup client MAC address from target IP
static uint8_t* lookup_nat_table(uint32_t ip) {
    for (int i = 0; i < MAX_NAT_ENTRIES; i++) {
        if (g_nat_table[i].ip == ip) {
            return g_nat_table[i].mac;
        }
    }
    return NULL;
}

// -------------------------------------------------------------------
// 1. Outbound Link Output Hook
// -------------------------------------------------------------------
static err_t mac_nat_sta_linkoutput(struct netif *netif, struct pbuf *p) {
    struct eth_hdr *eth = (struct eth_hdr *)p->payload;

    // Check if the target MAC belongs to an AP-connected client
    if (g_ap_netif && lookup_nat_table_by_mac(eth->dest.addr)) {
		
		log_dhcp_packet("REDIRECTED STA->AP", p);
	
		log_icmp_packet("REDIRECTED STA->AP", p);
		
		log_arp_packet("REDIRECTED STA->AP", p);
        
        // REWRITE: Change Source MAC from STA MAC to AP MAC
        SMEMCPY(eth->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

        // Redirect packet down to the AP Wi-Fi driver
        return g_ap_netif->linkoutput(g_ap_netif, p);
    }
    return original_sta_linkoutput(netif, p);
}

// -------------------------------------------------------------------
// 2. Outbound Hook (SoftAP Clients -> BL602 -> Upstream Router)
// -------------------------------------------------------------------
static err_t mac_nat_ap_input(struct pbuf *p, struct netif *netif) {
    if (!p || !p->payload || !g_sta_netif) return original_ap_input(p, netif);

// LOG ALL OUTBOUND DHCP PACKETS
    log_dhcp_packet("OUTBOUND AP->STA", p);
	
    log_icmp_packet("OUTBOUND AP->STA", p);
	
	log_arp_packet("OUTBOUND AP->STA", p);
	
	net_log_packet(true, (const uint8_t *)p->payload, p->tot_len);

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t type = lwip_ntohs(eth->type);
    int is_bcast_mcast = is_mcast_or_bcast_mac(eth->dest.addr);
    int is_dhcp_request = 0;

    // Detect outbound DHCP Request/Discover (UDP Port 67)
    if (type == ETHTYPE_IP && p->len >= SIZEOF_ETH_HDR + SIZEOF_IPH + sizeof(struct udp_hdr)) {
        struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        if (IPH_PROTO(iphdr) == 17) { // UDP
            uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
            struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)iphdr + ip_hdr_len);
            if (lwip_ntohs(udphdr->dest) == 67) {
                is_dhcp_request = 1;
            }
        }
    }

    // Learn client MAC mapping from incoming IP or ARP traffic
    if (type == ETHTYPE_IP) {
        struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        if (iphdr->src.addr != 0) {
            update_nat_table(iphdr->src.addr, eth->src.addr);
        }

        // Pass unicast packets targeting local BL602 IPs directly to local stack
        if (!is_bcast_mcast) {
            uint32_t dest_ip = iphdr->dest.addr;
            if (dest_ip == netif_ip4_addr(netif)->addr || 
               (g_sta_netif && dest_ip == netif_ip4_addr(g_sta_netif)->addr) ||
			   (lookup_nat_table(dest_ip) != NULL) ) {
				SMEMCPY(eth->dest.addr, g_sta_netif->hwaddr, ETH_HWADDR_LEN);
                return g_sta_netif->input(p, g_sta_netif);
            }
        }
    } 
    else if (type == ETHTYPE_ARP) {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint32_t target_ip, src_ip;
        memcpy(&target_ip, &arphdr->dipaddr, sizeof(target_ip));
        memcpy(&src_ip, &arphdr->sipaddr, sizeof(src_ip));

        if (src_ip != 0) {
            update_nat_table(src_ip, eth->src.addr);
        }


		if (target_ip == netif_ip4_addr(netif)->addr || 
		   (g_sta_netif && target_ip == netif_ip4_addr(g_sta_netif)->addr) ||
		   (lookup_nat_table(target_ip) != NULL) ) {
			return g_sta_netif->input(p, g_sta_netif);
		}
    }

    // Allocate copy for forwarding upstream over STA interface
    struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
	if (q) {
        pbuf_copy(q, p);
        struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

        if (type == ETHTYPE_ARP) {
            struct etharp_hdr *arphdr_q = (struct etharp_hdr *)((uint8_t *)q->payload + SIZEOF_ETH_HDR);
            memcpy(&arphdr_q->shwaddr, g_sta_netif->hwaddr, ETH_HWADDR_LEN);
        }

        // Rewrite L2 Source MAC to STA MAC for upstream transmission
        memcpy(eth_q->src.addr, g_sta_netif->hwaddr, ETH_HWADDR_LEN);

        // --- NEW FIX: Force DHCP Broadcast Flag ---
        if (is_dhcp_request) {
            struct ip_hdr *iphdr_q = (struct ip_hdr *)((uint8_t *)q->payload + SIZEOF_ETH_HDR);
            uint16_t ip_hdr_len_q = IPH_HL(iphdr_q) * 4;
            struct udp_hdr *udphdr_q = (struct udp_hdr *)((uint8_t *)iphdr_q + ip_hdr_len_q);
            
            // Offset to DHCP payload
            uint8_t *dhcp_payload = (uint8_t *)udphdr_q + sizeof(struct udp_hdr);

            // Read, modify, and write the DHCP flags (offset 10)
            uint16_t flags;
            memcpy(&flags, dhcp_payload + 10, 2);
            flags = lwip_ntohs(flags) | 0x8000; // Force broadcast bit
            flags = lwip_htons(flags);
            memcpy(dhcp_payload + 10, &flags, 2);

            // Zero out UDP checksum because we altered the UDP payload 
            // (0 means "no checksum" in IPv4 UDP, which is perfectly valid for DHCP)
            udphdr_q->chksum = 0;
        }
        // ------------------------------------------

        original_sta_linkoutput(g_sta_netif, q);
        pbuf_free(q);
    }

    // If Multicast or Broadcast, deliver to local AP stack UNLESS it's a DHCP request
    if (is_bcast_mcast) {
        if (is_dhcp_request) {
            pbuf_free(p); // Drop from local stack to avoid local dhcpd race conditions
            return ERR_OK;
        }
        return original_ap_input(p, netif);
    }

    pbuf_free(p);
    return ERR_OK;
}

// -------------------------------------------------------------------
// 3. Inbound Hook (Upstream Router -> BL602 -> SoftAP Clients)
// -------------------------------------------------------------------
static err_t mac_nat_sta_input(struct pbuf *p, struct netif *netif) {
    if (!p || !p->payload) return original_sta_input(p, netif);

    // LOG ALL OUTBOUND DHCP PACKETS
    log_dhcp_packet("INBOUND STA->AP", p);
	
	log_icmp_packet("INBOUND STA->AP", p);
	
	log_arp_packet("INBOUND STA->AP", p);
	
	net_log_packet(false, (const uint8_t *)p->payload, p->tot_len);
	

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t type = lwip_ntohs(eth->type);
    int is_bcast_mcast = is_mcast_or_bcast_mac(eth->dest.addr);

    // Loopback protection: Drop/ignore packets sent by BL602 itself
    if (memcmp(eth->src.addr, g_sta_netif->hwaddr, ETH_HWADDR_LEN) == 0 ||
        (g_ap_netif && memcmp(eth->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN) == 0)) {
        return original_sta_input(p, netif);
    }

    if (type == ETHTYPE_IP) {
        struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
        uint32_t dest_ip = iphdr->dest.addr;

        // Intercept Inbound DHCP Replies (UDP Port 68)
        if (IPH_PROTO(iphdr) == 17) { // UDP
            struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)iphdr + ip_hdr_len);

            if (lwip_ntohs(udphdr->dest) == 68) {
                uint8_t *dhcp_payload = (uint8_t *)udphdr + sizeof(struct udp_hdr);
                uint32_t yiaddr;
                uint8_t *chaddr = dhcp_payload + 28;
                memcpy(&yiaddr, dhcp_payload + 16, 4);

                // Read DHCP Flags field (offset 10 in DHCP header)
                uint16_t dhcp_flags;
                memcpy(&dhcp_flags, dhcp_payload + 10, 2);
                dhcp_flags = lwip_ntohs(dhcp_flags);

                // If DHCP offer/ack is for BL602's own STA MAC, process locally
                if (memcmp(chaddr, g_sta_netif->hwaddr, ETH_HWADDR_LEN) == 0) {
                    return original_sta_input(p, netif);
                }

                //if (yiaddr != 0) {
                //    update_nat_table(yiaddr, chaddr);
                //}

                if (g_ap_netif != NULL) {
                    struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
                    if (q) {
                        pbuf_copy(q, p);
                        struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

                        // FIX FOR ANDROID vs WINDOWS:
                        // Preserve L2 Broadcast if the incoming frame is broadcast OR
                        // if the DHCP Broadcast Flag (0x8000) is requested by the client.
                        if (is_bcast_mcast || (dhcp_flags & 0x8000)) {
                            memset(eth_q->dest.addr, 0xFF, ETH_HWADDR_LEN);
                        } else {
                            memcpy(eth_q->dest.addr, chaddr, ETH_HWADDR_LEN);
                        }

                        // Rewrite L2 Source MAC to SoftAP MAC
                        memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

                        g_ap_netif->linkoutput(g_ap_netif, q);
                        pbuf_free(q);
                    }
                    pbuf_free(p);
                    return ERR_OK;
                }
            }
        }

        // Unicast IPv4 handling
        if (!is_bcast_mcast) {
            if (dest_ip == netif_ip4_addr(netif)->addr || 
               (g_ap_netif && dest_ip == netif_ip4_addr(g_ap_netif)->addr)) {
                return original_sta_input(p, netif);
            }

            uint8_t *real_client_mac = lookup_nat_table(dest_ip);
            if (real_client_mac != NULL && g_ap_netif != NULL) {
                struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
                if (q) {
                    pbuf_copy(q, p);
                    struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

                    memcpy(eth_q->dest.addr, real_client_mac, ETH_HWADDR_LEN);
                    memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

                    g_ap_netif->linkoutput(g_ap_netif, q);
                    pbuf_free(q);
                }
                pbuf_free(p);
                return ERR_OK;
            }
        }
    } 
    else if (type == ETHTYPE_ARP) {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint16_t opcode = lwip_ntohs(arphdr->opcode);
        uint32_t target_ip;
        memcpy(&target_ip, &arphdr->dipaddr, sizeof(target_ip));

        uint8_t *real_client_mac = lookup_nat_table(target_ip);
        if (real_client_mac != NULL && g_ap_netif != NULL) {
            struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
            if (q) {
                pbuf_copy(q, p);
                struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;
				struct etharp_hdr *arp_q = (struct etharp_hdr *)((uint8_t *)q->payload + SIZEOF_ETH_HDR);

                memcpy(eth_q->dest.addr, real_client_mac, ETH_HWADDR_LEN);
                memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);
				
				//memcpy(&arp_q->shwaddr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

                if (opcode == ARP_REPLY) {
                    
                    memcpy(&arp_q->dhwaddr, real_client_mac, ETH_HWADDR_LEN);
                }

                g_ap_netif->linkoutput(g_ap_netif, q);
                pbuf_free(q);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // Generic Multicast/Broadcast Forwarding (STA -> SoftAP Clients)
    if (is_bcast_mcast && g_ap_netif != NULL) {
        if (type == ETHTYPE_IP) {
            struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
            // Broadcast storm filter: If source IP belongs to a SoftAP client, don't echo back
            if (lookup_nat_table(iphdr->src.addr) != NULL) {
                return original_sta_input(p, netif); 
            }
        }
        struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
        if (q) {
            pbuf_copy(q, p);
            struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

            // Rewrite L2 Source MAC to SoftAP MAC
            memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

            g_ap_netif->linkoutput(g_ap_netif, q);
            pbuf_free(q);
        }
        // Deliver original frame to local STA stack
        return original_sta_input(p, netif);
    }

    return original_sta_input(p, netif);
}



// -------------------------------------------------------------------
// 4. Initialization
// -------------------------------------------------------------------
void app_sta_init(const char *ssid, const char *key)
{
    wifi_interface_t sta_interface = wifi_mgmr_sta_enable();
    wifi_mgmr_sta_connect_mid(sta_interface, (char *)ssid, (char *)key, 
                              NULL, NULL, 0, 0, 1, WIFI_CONNECT_PMF_CAPABLE);

    vTaskDelay(pdMS_TO_TICKS(9000));

    struct netif *sta_netif = netif_find("st2");
    if (sta_netif == NULL) sta_netif = netif_find("st1");
    if (sta_netif == NULL) sta_netif = netif_find("st0");

    if (sta_netif != NULL) {
        g_sta_netif = sta_netif;
        printf("[MAC_NAT] Hooking lwIP netif for STA interface: %c%c%d\r\n", 
               sta_netif->name[0], sta_netif->name[1], sta_netif->num);

        original_sta_linkoutput = sta_netif->linkoutput;
        sta_netif->linkoutput   = mac_nat_sta_linkoutput;

        original_sta_input = sta_netif->input;
        sta_netif->input   = mac_nat_sta_input;

        printf("[MAC_NAT] L2 Translation Layer Active.\r\n");
    } else {
        dump_all_netifs();
        printf("[MAC_NAT] Error: STA netif interface not found!\r\n");
    }
}

// 2. Access Point Mode Initialization & Hooks
void app_ap_init(const char *ssid, const char *key, uint8_t channel) 
{
	//wifi_mgmr_ap_stop(NULL);
    wifi_interface_t ap_interface = wifi_mgmr_ap_enable();
    wifi_mgmr_ap_start_adv(ap_interface, (char *)ssid, 0, (char *)key, channel, 0);

    struct netif *ap_netif = netif_find("ap2");
    if (ap_netif == NULL) ap_netif = netif_find("ap1");
    if (ap_netif == NULL) ap_netif = netif_find("ap0");

    if (ap_netif != NULL) {
        g_ap_netif = ap_netif;
        printf("[MAC_NAT] Hooking lwIP netif for AP interface: %c%c%d\r\n", 
               ap_netif->name[0], ap_netif->name[1], ap_netif->num);

        original_ap_input = ap_netif->input;
        ap_netif->input   = mac_nat_ap_input;

        printf("[MAC_NAT] AP L2 Translation Layer Active.\r\n");
    } else {
        dump_all_netifs();
        printf("[MAC_NAT] Error: AP netif interface not found!\r\n");
    }
	if (g_sta_netif != NULL) {
		netif_set_default(g_sta_netif);
	}
}

// 3. Recovery AP-Only Mode Initialization
void app_recovery_init(uint8_t channel) 
{
    printf("[RECOVERY] Starting Recovery AP-Only Mode...\r\n");

    wifi_interface_t ap_interface = wifi_mgmr_ap_enable();
    wifi_mgmr_ap_start_adv(ap_interface, "BL602Proxy", 0, "BL602Proxy", channel, 1);
    
    // Optional: dhcpd_start(ap_interface);
}