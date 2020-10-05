#ifndef _DELTAIP_SOCK_H
#define _DELTAIP_SOCK_H

#define SOCK_FOREACH(entry) FOREACH(sock_base, entry)

#define AF_INET     1
#define AF_INET6    2

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_SEQPACKET  3
#define SOCK_RAW        4

#define SOCK_MAX        1024
#define TCP_SOCK_MAX    1024
#define UDP_SOCK_MAX    1024

#define SOCK_BUF_SIZE   8192

#include "common.h"

struct sock{
    struct sock *next;
    int fd;
    int type;
    struct ip_addr src;
    int sport;
    struct ip_addr dst;
    int dport;
    int state;
    int seq_num;
    int ack_num;
    //void *rbuf;
    //int rpos;
    //void *wbuf;
    //int wpos;
    struct sock_ops *ops;
    int (*recvfrom_handler)(void *, int, struct ip_addr *, int);
    int (*recv_handler)(int, void *, int);
};

struct sock_ops{
    int (*sendto)(struct sock *, void *, int, struct ip_addr *, int);
    int (*send)(struct sock *, void *, int);
    //int (*recv)(struct sock *, void *);
};

void sock_init();

int deltaip_socket(int domain, int type, int protocol);

int deltaip_bind(int sockfd, int port);

//int deltaip_listen(int sockfd, int backlog);

//int deltaip_recvfrom(int socket, void *buf, int buf_len,
//            int flags, struct sockaddr_in *address, int *address_len);

int deltaip_sendto(int sockfd, void *buf, int buf_len, struct ip_addr *dst, int port);

int deltaip_send(int sockfd, void *buf, int buf_len);

int deltaip_close(int socket);

int deltaip_register_recvfrom_handler(int sockfd, int (*handler)(void *, int, struct ip_addr *, int));

int deltaip_register_recv_handler(int sockfd, int (*handler)(int, void *, int));

struct sock *sock_lookup_fd(int sockfd);

struct sock *sock_lookup(int type, struct ip_addr *src, int sport, struct ip_addr *dst, int dport);

int sock_create(int domain, int type, int protocol);

void sock_close(int sockfd);

#endif
