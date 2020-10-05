#include "common.h"
#include "pktbuf.h"
#include "ip.h"
#include "udp.h"
#include "sock.h"

struct sock_ops udp_ops = {
    udp_sendto,
    NULL,
};

int udp_recv(struct pktbuf *pbuf){
    struct udp_hdr *udph = udphdr(pbuf);
    struct sock *s;
    struct ip_addr from;
    int data_len;
    char buf[8192];

    pbuf->hdr_offset += UDP_HDR_LEN;

    DBG(("udp header %u %u %u %04x\n", ntohs(udph->sport), ntohs(udph->dport),
        ntohs(udph->len), ntohs(udph->checksum)));

    if(!(s = sock_lookup(SOCK_DGRAM, NULL, udph->dport, NULL, 0))){
        pktbuf_free(pbuf);
        return 0;
    }

    data_len = pbuf->len - pbuf->hdr_offset;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, pbuf->data + pbuf->hdr_offset, data_len);
    from.addr = iphdr(pbuf)->src.addr;
    s->recvfrom_handler(buf, data_len, &from, udph->sport);
}

int udp_sendto(struct sock *sock, void *buf, int buf_len, struct ip_addr *dst, int port){
    struct pktbuf *pbuf = pktbuf_alloc(PKTBUF_PAD, UDP_HDR_LEN, buf_len);
    struct udp_hdr *udph = (struct udp_hdr *)pbuf->data;
    struct ip_hdr iph;

    udph->dport = port;
    udph->sport = sock->sport;
    udph->len = htons(UDP_HDR_LEN + buf_len);

    if(buf_len)
        memcpy(pbuf->data + UDP_HDR_LEN, buf, buf_len);

    pbuf->len += buf_len;

    memset(&iph, 0, IP_HDR_LEN);
    iph.dst.addr = dst->addr;
    iph.proto = IP_PROTO_UDP;

    ip_send(pbuf, &iph);
}
