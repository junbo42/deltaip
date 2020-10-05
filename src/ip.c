#include "common.h"
#include "pktbuf.h"
#include "ether.h"
#include "ip.h"
#include "route.h"
#include "iface.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

uint16_t checksum(void *hdr, int len){
    uint16_t *p = (uint16_t *)hdr;
    int sum = 0;
    while(len > 0) {
        sum += *p;
        sum = sum % 0xffff;
        p++;
        len -= 2;
    }

    return ~sum;
}

void ip_recv(struct pktbuf *pbuf) {
    struct ip_hdr *iph = iphdr(pbuf);
    pbuf->hdr_offset += IP_HDR_LEN;

    DBG(("ip header hdr_len:%d version:%x tos:%x len:%u id:%02x frag:%02x ttl:%u "
          "proto:%x checksum:%x src:%u dst:%u\n",
          iph->version, iph->hdr_len, iph->tos, ntohs(iph->len), ntohs(iph->id), ntohs(iph->frag),
          iph->ttl, iph->proto, ntohs(iph->checksum), ntohl(iph->src.addr), ntohl(iph->dst.addr)));

    if(ntohs(iph->frag) & 0x2fff){
        DBG(("drop fragmented ip packet\n"));
        pktbuf_free(pbuf);
        return;
    }

    switch (iph->proto) {
    case IP_PROTO_ICMP:
        icmp_recv(pbuf);
        break;
    case IP_PROTO_UDP:
        udp_recv(pbuf);
        break;
    case IP_PROTO_TCP:
        tcp_recv(pbuf);
        break;
    default:
        INFO(("proto %x not implemented\n"));
        break;
    }
}

int ip_send(struct pktbuf *pbuf, struct ip_hdr *opt) {
    static uint16_t count = 0;
    struct ip_hdr *iph;
    struct route *r;
    struct arp_entry *arp;
    struct ip_addr dst;

    dst.addr = opt->dst.addr;

    pktbuf_add_header(pbuf, IP_HDR_LEN);

    iph = (struct ip_hdr *)pbuf->data;
    iph->proto = opt->proto;
    iph->hdr_len = 5;
    iph->version = 4;
    iph->ttl = 64;
    iph->tos = 0;
    iph->len = htons(pbuf->len);
    iph->id = htons(count++);

    r = route_lookup(opt->dst.addr);
    if(!r){
        INFO(("destination unreachable\n"));
        pktbuf_free(pbuf);
        return 0;
    }

    if (opt->src.addr) {
        iph->src.addr = opt->src.addr;
    } else {
        iph->src.addr = r->iface->ipaddr->ip.addr;
    }

    if(r->gw.addr)
        arp = arp_lookup(r->iface, &r->gw);
    else
        arp = arp_lookup(r->iface, &dst);

    if(!arp)
        return 0;

    iph->dst.addr = opt->dst.addr;
    iph->checksum = checksum(iph, 20);
    pbuf->iface = r->iface;

    eth_send(&arp->eth_addr, &iface_base->eth_addr, ETH_TYPE_IP, pbuf);
}

int ip_fill_header(struct ip_hdr *iph) {
    struct route *r;

    r = route_lookup(iph->dst.addr);
    if(!r){
        INFO(("destination unreachable\n"));
        return 0;
    }

    if (iph->src.addr) {
        iph->src.addr = iph->src.addr;
    } else {
        iph->src.addr = r->iface->ipaddr->ip.addr;
    }

    return 1;
}
