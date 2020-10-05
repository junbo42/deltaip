#ifndef _DELTAIP_ICMP_H
#define _DELTAIP_ICMP_H
#include "pktbuf.h"

#define ICMP_TYPE_ECHO  8

struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t  id;
  uint16_t  sequence;
};

int icmp_recv(struct pktbuf *pbuf);

#endif
