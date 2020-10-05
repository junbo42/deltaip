#ifndef _DELTAIP_TCP_H
#define _DELTAIP_TCP_H

#define TCP_STATE_LISTEN        1
#define TCP_STATE_SYN_RECV      2
#define TCP_STATE_ESTABLISHED   3
#define TCP_STATE_CLOSE_WAIT    4
#define TCP_STATE_LAST_ACK      5

#define TCP_WIN_SIZE ntohs(65535)

#include "pktbuf.h"
#include "sock.h"

struct tcp_hdr{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t res1:4;
    uint16_t hdr_len:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t res2:3;
    uint16_t win;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed));

int tcp_recv(struct pktbuf *pbuf);

int tcp_send(struct sock *sock, void *buf, int buf_len);

extern struct sock_ops tcp_ops;

#endif
