#ifndef _DELTAIP_ARP_H
#define _DELTAIP_ARP_H
#include "pktbuf.h"
#include "iface.h"

#define ARP_TABLE_SIZE   128

#define ARP_STATE_EMPTY  0x00
#define ARP_STATE_STABLE 0x01
#define ARP_STATE_STATIC 0x02

#define ARP_OP_REQUEST   0x01
#define ARP_OP_REPLY     0x02

#define ARP_TIMEOUT      300
#define ARP_FOREACH(entry) FOREACH(arp_base, entry)

struct arp_hdr {
  uint16_t hwtype;
  uint16_t proto;
  uint8_t  hwlen;
  uint8_t  protolen;
  uint16_t opcode;
  struct eth_addr shwaddr;
  struct ip_addr sipaddr;
  struct eth_addr dhwaddr;
  struct ip_addr dipaddr;
} __attribute__((packed));

struct arp_entry {
    struct ip_addr ip_addr;
    struct eth_addr eth_addr;
    uint8_t state;
    struct arp_entry *next;
    long update_time;
    long last_time;
    struct iface *iface;
};

void arp_init();
int arp_recv(struct pktbuf *buf);
struct arp_entry *arp_add(struct iface *ifa, const struct ip_addr *ipaddr, struct eth_addr *ethaddr);
void arp_update_entry(struct iface *ifa, const struct ip_addr *ipaddr, struct eth_addr *ethaddr);
void arp_task();
struct arp_entry *arp_lookup(struct iface *ifa, const struct ip_addr *ipaddr);

extern struct arp_entry *arp_base;

#endif
