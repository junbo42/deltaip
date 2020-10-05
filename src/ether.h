#ifndef _DELTAIP_ETHER_H
#define _DELTAIP_ETHER_H
#include "pktbuf.h"

struct eth_hdr {
  struct eth_addr dst;
  struct eth_addr src;
  uint16_t type;
} __attribute__((packed));

void eth_send(struct eth_addr *dst, struct eth_addr *src, int type, struct pktbuf *pbuf);
void eth_recv(struct pktbuf *buf);

#endif
