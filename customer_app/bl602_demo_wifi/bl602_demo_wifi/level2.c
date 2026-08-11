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

    printf("\n=== Dumping Registered lwIP Interfaces ===\n");
    if (netif_list == NULL) {
        printf("No netif interfaces registered yet!\n");
        return;
    }

    for (curr = netif_list; curr != NULL; curr = curr->next) {
        printf("Interface: %c%c%d\n", curr->name[0], curr->name[1], curr->num);
        printf("  - Address: %p\n", (void *)curr);
        printf("  - Flags  : 0x%02X (Up: %s, Link Up: %s)\n",
               curr->flags,
               netif_is_up(curr) ? "YES" : "NO",
               netif_is_link_up(curr) ? "YES" : "NO");
        printf("  - IP     : %s\n", ipaddr_ntoa(&curr->ip_addr));
    }
    printf("=========================================\n\n");
}

// Mapping table entry for tracking client MACs behind the BL602
typedef struct {
    uint32_t ip;         // Network byte order IPv4 address
    uint8_t  mac[6];      // Actual hardware MAC address of downstream client
    uint32_t last_seen;  // Timestamp for entry aging
} nat_entry_t;

static nat_entry_t g_nat_table[MAX_NAT_ENTRIES];
static netif_linkoutput_fn original_sta_linkoutput = NULL;
static netif_input_fn      original_sta_input      = NULL;

static netif_linkoutput_fn original_ap_linkoutput = NULL;
static netif_input_fn      original_ap_input      = NULL;





static void log_icmp_packet(const char *dir, struct pbuf *p) {
    if (p->len < SIZEOF_ETH_HDR + SIZEOF_IPH) return;

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    if (lwip_ntohs(eth->type) != ETHTYPE_IP) return;

    struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
    
    // Check if IP Protocol is ICMP (1)
    if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
        uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
        struct icmp_echo_hdr *icmp = (struct icmp_echo_hdr *)((uint8_t *)iphdr + ip_hdr_len);

        char src_str[16], dst_str[16];
        ip4addr_ntoa_r((const ip4_addr_t *)&iphdr->src, src_str, sizeof(src_str));
        ip4addr_ntoa_r((const ip4_addr_t *)&iphdr->dest, dst_str, sizeof(dst_str));

        const char *type_str = (icmp->type == ICMP_ECHO) ? "ECHO_REQ" :
                               (icmp->type == ICMP_ER)   ? "ECHO_REPLY" : "OTHER";

        printf("[%s ICMP] %s | %s -> %s | ID: %d | Seq: %d\n",
               dir, type_str, src_str, dst_str,
               lwip_ntohs(icmp->id), lwip_ntohs(icmp->seqno));
    }
}


// Helper: Update or insert a MAC-to-IP mapping
static void update_nat_table(uint32_t ip, const uint8_t *mac) {
    if (ip == 0) return;
    for (int i = 0; i < MAX_NAT_ENTRIES; i++) {
        if (g_nat_table[i].ip == ip || g_nat_table[i].ip == 0) {
            g_nat_table[i].ip = ip;
            memcpy(g_nat_table[i].mac, mac, 6);
            return;
        }
    }
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

// Helper: Send a Proxy ARP Reply on behalf of a downstream client
static void send_proxy_arp_reply(struct netif *sta_netif, 
                                 const uint8_t *req_src_mac, 
                                 uint32_t req_src_ip, 
                                 uint32_t target_ip) 
{
    u16_t frame_len = SIZEOF_ETH_HDR + SIZEOF_ETHARP_HDR;
    struct pbuf *p = pbuf_alloc(PBUF_RAW_TX, frame_len, PBUF_RAM);
    if (!p) return;
	
	printf("sending arp reply\r\n");

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    struct etharp_hdr *arp = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);

    // Ethernet Header: Target = Requester MAC, Source = BL602 STA MAC
    memcpy(eth->dest.addr, req_src_mac, ETH_HWADDR_LEN);
    memcpy(eth->src.addr, sta_netif->hwaddr, ETH_HWADDR_LEN);
    eth->type = lwip_htons(ETHTYPE_ARP);

    // ARP Header
    arp->hwtype   = lwip_htons(1);
    arp->proto    = lwip_htons(ETHTYPE_IP);
    arp->hwlen    = ETH_HWADDR_LEN;
    arp->protolen = 4;
    arp->opcode   = lwip_htons(ARP_REPLY);

    // Proxy Sender Info (BL602 STA MAC + Client IP)
    memcpy(&arp->shwaddr, sta_netif->hwaddr, ETH_HWADDR_LEN);
    memcpy(&arp->sipaddr, &target_ip, 4);

    // Requester Target Info
    memcpy(&arp->dhwaddr, req_src_mac, ETH_HWADDR_LEN);
    memcpy(&arp->dipaddr, &req_src_ip, 4);

    original_sta_linkoutput(sta_netif, p);
    pbuf_free(p);
}
// -------------------------------------------------------------------

// 1. Outbound Hook (SoftAP Clients -> BL602 -> Upstream STA Router)
// -------------------------------------------------------------------
static err_t mac_nat_sta_linkoutput(struct netif *netif, struct pbuf *p) {
    if (p == NULL || p->payload == NULL) {
        return original_sta_linkoutput(netif, p);
    }

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t type = lwip_ntohs(eth->type);

    // Outbound IPv4 Frame
    if (type == ETHTYPE_IP) {
        struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint32_t src_ip = iphdr->src.addr;

        // Learn downstream client's IP <-> MAC mapping
        update_nat_table(src_ip, eth->src.addr);

        // Rewrite Source MAC header to BL602's STA MAC address
        memcpy(eth->src.addr, netif->hwaddr, ETH_HWADDR_LEN);
    }
    // Outbound ARP Frame
    else if (type == ETHTYPE_ARP) {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint32_t src_ip;
        memcpy(&src_ip, &arphdr->sipaddr, sizeof(src_ip));

        // Learn client mapping from ARP request/reply
        update_nat_table(src_ip, eth->src.addr);

        // Rewrite L2 Source MAC
        memcpy(eth->src.addr, netif->hwaddr, ETH_HWADDR_LEN);
        // Rewrite ARP Payload: Sender Hardware Address (SHA)
        memcpy(&arphdr->shwaddr, netif->hwaddr, ETH_HWADDR_LEN);
    }

    // Forward frame to BL602 physical Wi-Fi transmitter
    return original_sta_linkoutput(netif, p);
}

static err_t mac_nat_ap_input(struct pbuf *p, struct netif *netif) {
    if (!p || !p->payload || !g_sta_netif) return original_ap_input(p, netif);

    log_icmp_packet("OUTBOUND AP->STA", p);

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t type = lwip_ntohs(eth->type);

    if (type == ETHTYPE_ARP) {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint32_t target_ip;
        memcpy(&target_ip, &arphdr->dipaddr, sizeof(target_ip));

        // Allow local ARP requests targeting BL602 AP IP to pass to local lwIP stack
        if (target_ip == netif_ip4_addr(netif)->addr) {
            return original_ap_input(p, netif);
        }

        uint32_t src_ip;
        memcpy(&src_ip, &arphdr->sipaddr, sizeof(src_ip));
        update_nat_table(src_ip, eth->src.addr);
    }

    struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
    if (!q) {
        pbuf_free(p);
        return ERR_MEM;
    }
    pbuf_copy(q, p);

    struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

    if (type == ETHTYPE_IP) {
        struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)q->payload + SIZEOF_ETH_HDR);
        if (iphdr->src.addr != 0) {
            update_nat_table(iphdr->src.addr, eth_q->src.addr);
        }
    } else if (type == ETHTYPE_ARP) {
        struct etharp_hdr *arphdr_q = (struct etharp_hdr *)((uint8_t *)q->payload + SIZEOF_ETH_HDR);
        memcpy(&arphdr_q->shwaddr, g_sta_netif->hwaddr, ETH_HWADDR_LEN);
    }

    // Rewrite L2 Source MAC to STA MAC for transmission to upstream router
    memcpy(eth_q->src.addr, g_sta_netif->hwaddr, ETH_HWADDR_LEN);

    original_sta_linkoutput(g_sta_netif, q);

    pbuf_free(q);
    pbuf_free(p);
    return ERR_OK;
}

// -------------------------------------------------------------------
// Updated Inbound Hook (Upstream Router -> BL602 -> SoftAP Clients)
// -------------------------------------------------------------------
static err_t mac_nat_sta_input(struct pbuf *p, struct netif *netif) {
    if (!p || !p->payload) return original_sta_input(p, netif);

    log_icmp_packet("INBOUND STA->AP", p);

    struct eth_hdr *eth = (struct eth_hdr *)p->payload;
    uint16_t type = lwip_ntohs(eth->type);

    if (type == ETHTYPE_IP) {
        struct ip_hdr *iphdr = (struct ip_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;

        // Check for UDP traffic (DHCP)
        if (IPH_PROTO(iphdr) == 17) { // 17 = UDP
            struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)iphdr + ip_hdr_len);

            // Intercept Inbound DHCP Replies (UDP Port 68)
            if (lwip_ntohs(udphdr->dest) == 68) {
                uint8_t *dhcp_payload = (uint8_t *)udphdr + sizeof(struct udp_hdr);
                
                uint32_t yiaddr;
                uint8_t *chaddr = dhcp_payload + 28; // Client MAC offset in DHCP header
                memcpy(&yiaddr, dhcp_payload + 16, 4); // Offered IP offset in DHCP header

                // Automatically bind client MAC to the newly assigned IP
                if (yiaddr != 0) {
                    update_nat_table(yiaddr, chaddr);
                }

                if (g_ap_netif != NULL) {
                    struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
                    if (q) {
                        pbuf_copy(q, p);
                        struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

                        // Forward to client MAC (or broadcast if dest MAC is broadcast)
                        if (!ip4_addr_isbroadcast((const ip4_addr_t *)&iphdr->dest, netif)) {
                            memcpy(eth_q->dest.addr, chaddr, ETH_HWADDR_LEN);
                        }
                        // CRITICAL: Rewrite L2 Source MAC to SoftAP MAC
                        memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

                        g_ap_netif->linkoutput(g_ap_netif, q);
                        pbuf_free(q);
                    }
                    pbuf_free(p);
                    return ERR_OK;
                }
            }
        }

        // Normal Inbound Unicast IPv4 Data
        uint32_t dest_ip = iphdr->dest.addr;
        uint8_t *real_client_mac = lookup_nat_table(dest_ip);
        if (real_client_mac != NULL && g_ap_netif != NULL) {
            struct pbuf *q = pbuf_alloc(PBUF_RAW_TX, p->tot_len, PBUF_RAM);
            if (q) {
                pbuf_copy(q, p);
                struct eth_hdr *eth_q = (struct eth_hdr *)q->payload;

                memcpy(eth_q->dest.addr, real_client_mac, ETH_HWADDR_LEN);
                // CRITICAL: Rewrite L2 Source MAC to SoftAP MAC
                memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);

                g_ap_netif->linkoutput(g_ap_netif, q);
                pbuf_free(q);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    } 
    else if (type == ETHTYPE_ARP) {
        struct etharp_hdr *arphdr = (struct etharp_hdr *)((uint8_t *)p->payload + SIZEOF_ETH_HDR);
        uint16_t opcode = lwip_ntohs(arphdr->opcode);

        if (opcode == ARP_REQUEST) {
            uint32_t target_ip, sender_ip;
            memcpy(&target_ip, &arphdr->dipaddr, sizeof(target_ip));
            memcpy(&sender_ip, &arphdr->sipaddr, sizeof(sender_ip));

            if (lookup_nat_table(target_ip) != NULL) {
                send_proxy_arp_reply(netif, eth->src.addr, sender_ip, target_ip);
                pbuf_free(p);
                return ERR_OK;
            }
        } else if (opcode == ARP_REPLY) {
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
                    // CRITICAL: Rewrite L2 Source MAC to SoftAP MAC
                    memcpy(eth_q->src.addr, g_ap_netif->hwaddr, ETH_HWADDR_LEN);
                    memcpy(&arp_q->dhwaddr, real_client_mac, ETH_HWADDR_LEN);

                    g_ap_netif->linkoutput(g_ap_netif, q);
                    pbuf_free(q);
                }
                pbuf_free(p);
                return ERR_OK;
            }
        }
    }

    return original_sta_input(p, netif);
}
// -------------------------------------------------------------------
// 3. System Initialization (AP+STA Startup + Hook Injection)
// -------------------------------------------------------------------
void app_mac_nat_init(const char *upstream_ssid, const char *upstream_key,
                      const char *softap_ssid,   const char *softap_key) 
{
    printf("[MAC_NAT] Starting BL602 AP+STA Concurrent Mode...\n");

    // Initialize Wi-Fi subsystem (bl_iot_sdk API)
    //wifi_mgmr_start_background();

    // 1. Configure SoftAP (Local SSID for client connections)
    wifi_interface_t ap_interface = wifi_mgmr_ap_enable();
    wifi_mgmr_ap_start(ap_interface, (char *)softap_ssid, 0, (char *)softap_key, 6);

    // 2. Configure Station (Connects to upstream router)
    wifi_interface_t sta_interface = wifi_mgmr_sta_enable();
    wifi_mgmr_sta_connect_mid(sta_interface, (char *)upstream_ssid, (char *)upstream_key, 
                          NULL, NULL, 0, 0, 1, WIFI_CONNECT_PMF_CAPABLE);

	vTaskDelay(10000);
    // 3. Retrieve lwIP Network Interfaces (BL602 maps interface "st1" / "st0")
    struct netif *sta_netif = netif_find("st2");
    if (sta_netif == NULL) {
        sta_netif = netif_find("st1"); // Fallback check
        if (sta_netif == NULL) {
        sta_netif = netif_find("st0"); // Fallback check
    }
    }

    if (sta_netif != NULL) {
		g_sta_netif = sta_netif;
        printf("[MAC_NAT] Hooking lwIP netif for STA interface: %c%c%d\n", 
               sta_netif->name[0], sta_netif->name[1], sta_netif->num);

        // Intercept Outbound Frames (linkoutput hook)
        original_sta_linkoutput = sta_netif->linkoutput;
        sta_netif->linkoutput   = mac_nat_sta_linkoutput;

        // Intercept Inbound Frames (input hook)
        original_sta_input = sta_netif->input;
        sta_netif->input   = mac_nat_sta_input;

        printf("[MAC_NAT] L2 Translation Layer Active.\n");
    } else {
		dump_all_netifs();
        printf("[MAC_NAT] Error: STA netif interface not found!\n");
    }
	
	    struct netif *ap_netif = netif_find("ap2");
    if (ap_netif == NULL) {
        ap_netif = netif_find("ap1"); // Fallback check
        if (ap_netif == NULL) {
        ap_netif = netif_find("ap0"); // Fallback check
		}
    }
	if (ap_netif != NULL) {
		g_ap_netif = ap_netif;
        printf("[MAC_NAT] Hooking lwIP netif for AP interface: %c%c%d\n", 
               ap_netif->name[0], ap_netif->name[1], ap_netif->num);


        // Intercept Inbound Frames (input hook)
        original_ap_input = ap_netif->input;
        ap_netif->input   = mac_nat_ap_input;

        printf("[MAC_NAT] AP L2 Translation Layer Active.\n");
    } else {
		dump_all_netifs();
        printf("[MAC_NAT] Error: AP netif interface not found!\n");
    }
}