#ifndef _DELTAIP_COMMON_H
#define _DELTAIP_COMMON_H

/* should be deleted later */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define ETH_HDR_LEN     14
#define ARP_HDR_LEN     28
#define IP_HDR_LEN      20
#define ICMP_HDR_LEN    8
#define UDP_HDR_LEN     8
#define TCP_HDR_LEN     20
#define PKTBUF_LEN      sizeof(struct pktbuf)
#define PKTBUF_PAD      sizeof(struct pktbuf) + ETH_HDR_LEN + IP_HDR_LEN

#define ethhdr(pbuf) ((struct eth_hdr *) (pbuf->data))
#define arphdr(pbuf) ((struct arp_hdr *) (pbuf->data + ETH_HDR_LEN))
#define iphdr(pbuf) ((struct ip_hdr *) (pbuf->data + ETH_HDR_LEN))
#define icmphdr(pbuf) ((struct icmp_hdr *) (pbuf->data + ETH_HDR_LEN + IP_HDR_LEN))
#define udphdr(pbuf) ((struct udp_hdr *) (pbuf->data + ETH_HDR_LEN + IP_HDR_LEN))
#define tcphdr(pbuf) ((struct tcp_hdr *) (pbuf->data + ETH_HDR_LEN + IP_HDR_LEN))

#define FOREACH(base, entry) \
    for((entry) = (base); (entry); (entry = entry->next))

#ifdef DEBUG
#define DBG(M) printf M
#else
#define DBG(M)
#endif

#define INFO(M) printf M

#define PRINT(M) printf M

typedef unsigned char uint8_t;                                                                                                           
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long int uint64_t;

struct eth_addr {
    uint8_t addr[6];
};

struct ip_addr {
    uint32_t addr;
};

void print_pkt(uint8_t *, int);

void panic(char *);

void deltaip_task();

void deltaip_init();

long gettime();

char *ntoa(uint32_t src, char *dst);

int htons(uint16_t x);

int ntohs(uint16_t x);

int htonl(uint32_t x);

int ntohl(uint32_t x);

extern unsigned long jiffies;

#define ETH_TYPE_ARP    0x0806
#define ETH_TYPE_IP     0x0800
#define ETH_TYPE_IPV6   0x86dd

#endif
