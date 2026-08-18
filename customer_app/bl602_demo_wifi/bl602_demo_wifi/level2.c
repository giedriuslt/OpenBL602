#include <stdio.h>
#include <string.h>
#include <wifi_mgmr_ext.h>
#include <FreeRTOS.h>
#include <task.h>
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ethernet.h"
#include "lwip/prot/icmp.h"
#include "lwip/prot/udp.h"
#include "lwip/prot/etharp.h"
#include "lwip/prot/ip4.h"

#define MAX_NAT_ENTRIES 16

#ifndef SIZEOF_IPH
#define SIZEOF_IPH sizeof(struct ip_hdr)
#endif

#ifndef IP_PROTO_ICMP
#define IP_PROTO_ICMP 1
#endif

static struct netif *g_ap_netif  = NULL;
static struct netif *g_sta_netif = NULL;

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
               (g_sta_netif && dest_ip == netif_ip4_addr(g_sta_netif)->addr)) {
                return original_ap_input(p, netif);
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

        if (!is_bcast_mcast) {
            if (target_ip == netif_ip4_addr(netif)->addr || 
               (g_sta_netif && target_ip == netif_ip4_addr(g_sta_netif)->addr) ||
               (lookup_nat_table(target_ip) != NULL)) {
                return original_ap_input(p, netif);
            }
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

                if (yiaddr != 0) {
                    update_nat_table(yiaddr, chaddr);
                }

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
void app_mac_nat_init(const char *upstream_ssid, const char *upstream_key,
                      const char *softap_ssid,   const char *softap_key) 
{
    printf("[MAC_NAT] Starting BL602 AP+STA Concurrent Mode...\r\n");

    wifi_interface_t ap_interface = wifi_mgmr_ap_enable();
    wifi_mgmr_ap_start(ap_interface, (char *)softap_ssid, 0, (char *)softap_key, 6);

    wifi_interface_t sta_interface = wifi_mgmr_sta_enable();
    wifi_mgmr_sta_connect_mid(sta_interface, (char *)upstream_ssid, (char *)upstream_key, 
                              NULL, NULL, 0, 0, 1, WIFI_CONNECT_PMF_CAPABLE);

    vTaskDelay(10000);

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
}