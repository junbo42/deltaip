#include "common.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

void eth_recv(struct pktbuf *pbuf){
    struct eth_hdr *ethh;

    ethh = (struct eth_hdr *)pbuf->data;
    pbuf->hdr_offset += ETH_HDR_LEN;

    DBG(("ether_recv dst:%02x:%02x:%02x:%02x:%02x:%02x src:%02x:%02x:%02x:%02x:%02x:%02x type:%04x\n",
        ethh->dst.addr[0], ethh->dst.addr[1], ethh->dst.addr[2], ethh->dst.addr[3], ethh->dst.addr[4], ethh->dst.addr[5],
        ethh->src.addr[0], ethh->src.addr[1], ethh->src.addr[2], ethh->src.addr[3], ethh->src.addr[4], ethh->src.addr[5],
        ntohs(ethh->type)));

    if(pbuf->len > 1500){
        pktbuf_free(pbuf);
        return;
    }

    switch(ntohs(ethh->type)){
    case ETH_TYPE_ARP:
        arp_recv(pbuf);
        break;
    case ETH_TYPE_IP:
        ip_recv(pbuf);
        break;
    case ETH_TYPE_IPV6:
        INFO(("ipv6 not implemented\n"));
        break;
    default:
        INFO(("unknow protocol %04x\n", ntohs(ethh->type)));
        break;
    }
}

void eth_send(struct eth_addr *dst, struct eth_addr *src, int type, struct pktbuf *pbuf){
    pktbuf_add_header(pbuf, ETH_HDR_LEN);

    struct eth_hdr * ethh = (struct eth_hdr *)pbuf->data;
    if(!dst)
        memset(&ethh->dst, 255, 6);
    else
        memcpy(&ethh->dst, dst, 6);
    memcpy(&ethh->src, src, 6);
    ethh->type = htons(type);

    write(pbuf->iface->fd, pbuf->data, pbuf->len);

    pktbuf_free(pbuf);
}
