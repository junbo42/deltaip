#ifndef _DELTAIP_IP_H
#define _DELTAIP_IP_H
#include "common.h"
#include "pktbuf.h"
#include "ether.h"

#define IP_PROTO_ICMP    1
#define IP_PROTO_TCP     6
#define IP_PROTO_UDP     17

#define ICMP_TYPE_ECHO  8

#define IP_RF 0x8000U        /* reserved fragment flag */
#define IP_DF 0x4000U        /* don't fragment flag */
#define IP_MF 0x2000U        /* more fragments flag */
#define IP_OFFMASK 0x1fffU   /* mask for fragmenting bits */

struct ip_hdr {
    uint8_t     hdr_len:4;
    uint8_t     version:4;
    uint8_t     tos;
    uint16_t    len;
    uint16_t    id;
    uint16_t    frag;
    uint8_t     ttl;
    uint8_t     proto;
    uint16_t    checksum;
    struct ip_addr   src;
    struct ip_addr   dst;
} __attribute__((packed));

uint16_t checksum(void *hdr, int len);

void ip_recv(struct pktbuf *buf);

int ip_send(struct pktbuf *, struct ip_hdr *);

int ip_fill_header(struct ip_hdr *iph);

#endif
