#ifndef _DELTAIP_UDP_H
#define _DELTAIP_UDP_H
#include "pktbuf.h"
#include "sock.h"

struct udp_hdr {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t checksum;
};

int udp_recv(struct pktbuf *pbuf);

int udp_sendto(struct sock *sock, void *buf, int buf_len, struct ip_addr *dst, int port);

extern struct sock_ops udp_ops;

#endif
