#include "common.h"
#include "pktbuf.h"
#include "ether.h"
#include "ip.h"
#include "icmp.h"

static int icmp_reply(struct pktbuf *pbuf_in){
    int data_len;
    struct ip_hdr *iph;
    struct ip_hdr opt;
    struct pktbuf *pbuf;
    struct icmp_hdr *icmph;

    data_len = pbuf_in->len - pbuf_in->hdr_offset;
    pbuf = pktbuf_alloc2(ETH_HDR_LEN + IP_HDR_LEN + ICMP_HDR_LEN + data_len);
    pbuf->data += ETH_HDR_LEN + IP_HDR_LEN;
    pbuf->len += ICMP_HDR_LEN;

    icmph = (struct icmp_hdr *)pbuf->data;
    icmph->id = icmphdr(pbuf_in)->id;
    icmph->sequence = icmphdr(pbuf_in)->sequence;
    memcpy(pbuf->data + ICMP_HDR_LEN, pbuf_in->data + pbuf_in->hdr_offset, data_len);

    pbuf->len += data_len;
    icmph->checksum = checksum(icmph, 8 + data_len);

    memset(&opt, 0, IP_HDR_LEN);
    opt.proto = IP_PROTO_ICMP;
    opt.dst.addr = iphdr(pbuf_in)->src.addr;
    opt.src.addr = iphdr(pbuf_in)->dst.addr;

    ip_send(pbuf, &opt);
}

int icmp_recv(struct pktbuf *pbuf){
    struct ip_hdr *iph = iphdr(pbuf);
    struct icmp_hdr *icmph = icmphdr(pbuf);
    pbuf->hdr_offset += ICMP_HDR_LEN;

    DBG(("icmp header type:%x code:%x checksum:%x id:%u sequence:%u\n",
         icmph->type, icmph->code, htons(icmph->checksum), ntohs(icmph->id), ntohs(icmph->sequence)));

    switch(icmph->type){
    case ICMP_TYPE_ECHO:
        icmp_reply(pbuf);
        break;
    default:
        INFO(("icmp_recv unknown icmp type %x\n", icmph->type));
    }

    pktbuf_free(pbuf);
}

int icmp_send(struct pktbuf *pbuf, struct icmp_hdr *icmph){
}
