#include "common.h"
#include "pktbuf.h"
#include "ip.h"
#include "tcp.h"
#include "sock.h"

struct sock_ops tcp_ops = {
    NULL,
    tcp_send,
};

static uint16_t tcp_checksum(struct ip_hdr *iph, void *tcph, int len){
    uint16_t *p = (uint16_t *)tcph;
    int sum = 0;
    int src = iph->src.addr;
    int dst = iph->dst.addr;

    sum += (src >> 16) + (src & 0xffff);
    sum += (dst >> 16) + (dst & 0xffff);
    sum += ntohs(IP_PROTO_TCP);
    sum += ntohs(len);

    while(len > 0) {
        sum += *p;
        sum = sum % 0xffff;
        p++;
        len -= 2;
    }

    return ~sum;
}

static void tcp_rst(struct pktbuf *pbufin){
    struct pktbuf *pbuf;
    struct tcp_hdr *tcph;
    struct ip_hdr iph;

    pbuf = pktbuf_alloc2(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    pbuf->data += ETH_HDR_LEN + IP_HDR_LEN;
    pbuf->len += TCP_HDR_LEN;

    tcph = (struct tcp_hdr *)pbuf->data;
    tcph->dport = tcphdr(pbufin)->sport;
    tcph->sport = tcphdr(pbufin)->dport;
    tcph->hdr_len = 5;
    tcph->seq_num = 0;
    tcph->ack_num = htonl(ntohl(tcphdr(pbufin)->seq_num) + 1);
    tcph->ack = 1;
    tcph->rst = 1;
    tcph->syn = 0;
    tcph->win = TCP_WIN_SIZE;

    memset(&iph, 0, IP_HDR_LEN);
    iph.proto = IP_PROTO_TCP;
    iph.dst.addr = iphdr(pbufin)->src.addr;

    if(!ip_fill_header(&iph)){
        return;
    }

    tcph->checksum = tcp_checksum(&iph, tcph, 20);
    ip_send(pbuf, &iph);
}

static void tcp_new_conn(struct sock *s, struct pktbuf *pbufin){
    struct pktbuf *pbuf;
    struct tcp_hdr *tcph;
    struct ip_hdr iph;
    struct sock *news;
    int newfd;

    DBG(("tcp header sport:%u dport:%u seq_num:%u ack_num:%u hdr_len:%u "
         "ack:%u psh:%u rst:%u syn:%u fin:%u win:%u checksum:%04x\n",
         ntohs(tcphdr(pbufin)->sport), ntohs(tcphdr(pbufin)->dport), ntohl(tcphdr(pbufin)->seq_num),
         ntohl(tcphdr(pbufin)->ack_num), tcphdr(pbufin)->hdr_len, tcphdr(pbufin)->ack, tcphdr(pbufin)->psh,
         tcphdr(pbufin)->rst, tcphdr(pbufin)->syn, tcphdr(pbufin)->fin, ntohs(tcphdr(pbufin)->win), ntohs(tcphdr(pbufin)->checksum)));

    if(s->state == TCP_STATE_LISTEN && !tcphdr(pbufin)->syn){
        tcp_rst(pbufin);
        return;
    }

    pbuf = pktbuf_alloc2(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
    pbuf->data += ETH_HDR_LEN + IP_HDR_LEN;
    pbuf->len += TCP_HDR_LEN;

    tcph = (struct tcp_hdr *)pbuf->data;
    tcph->dport = tcphdr(pbufin)->sport;
    tcph->sport = s->sport;
    tcph->hdr_len = 5;
    tcph->seq_num = 0;
    tcph->ack_num = htonl(ntohl(tcphdr(pbufin)->seq_num) + 1);
    tcph->syn = 1;
    tcph->ack = 1;
    tcph->win = TCP_WIN_SIZE;

    memset(&iph, 0, IP_HDR_LEN);
    iph.proto = IP_PROTO_TCP;
    iph.dst.addr = iphdr(pbufin)->src.addr;

    if(!ip_fill_header(&iph)){
        return;
    }

    tcph->checksum = tcp_checksum(&iph, tcph, 20);
    newfd = sock_create(AF_INET, SOCK_STREAM, 0);
    news = sock_lookup_fd(newfd);

    if(!news)
        return;

    news->ack_num = htonl(ntohl(tcphdr(pbufin)->seq_num) + 1);
    news->state = TCP_STATE_SYN_RECV;
    news->dport = tcphdr(pbufin)->sport;
    news->dst.addr =  iphdr(pbufin)->src.addr;
    news->sport =  tcphdr(pbufin)->dport;
    news->recv_handler = s->recv_handler;
    DBG(("tcp_new_conn %p %p\n", s, news));

    ip_send(pbuf, &iph);
}

static void tcp_commit_conn(struct sock *s, struct pktbuf *pbufin){
    DBG(("tcp_commit_conn %p\n", s));
    s->seq_num = ntohl(tcphdr(pbufin)->ack_num);
    s->state = TCP_STATE_ESTABLISHED;
}

static void tcp_process_conn(struct sock *s, struct pktbuf *pbufin){
    DBG(("tcp_process_conn %p\n", s));
    struct pktbuf *pbuf;
    struct tcp_hdr *tcph, *tcphin;
    int data_len;

    tcphin = tcphdr(pbufin);
    data_len = pbufin->len - pbufin->hdr_offset;

    if((tcphin->ack || tcphin->psh) && data_len){
        struct ip_hdr iph;
        char buf[8192];

        pbuf = pktbuf_alloc2(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        pbuf->data += ETH_HDR_LEN + IP_HDR_LEN;
        pbuf->len += TCP_HDR_LEN;

        tcph = (struct tcp_hdr *)pbuf->data;
        tcph->dport = s->dport;
        tcph->sport = s->sport;
        tcph->hdr_len = 5;
        tcph->seq_num = htonl(s->seq_num);
        tcph->ack_num = htonl(ntohl(tcphin->seq_num) + data_len);
        tcph->ack = 1;
        tcph->win = TCP_WIN_SIZE;
        s->ack_num = ntohl(tcphin->seq_num) + data_len;

        memset(&iph, 0, IP_HDR_LEN);
        iph.proto = IP_PROTO_TCP;
        iph.dst.addr = iphdr(pbufin)->src.addr;

        if(!ip_fill_header(&iph))
            return;

        tcph->checksum = tcp_checksum(&iph, tcph, 20);
        ip_send(pbuf, &iph);

        memset(buf, 0, sizeof(buf));
        memcpy(buf, pbufin->data + pbufin->hdr_offset, data_len);
        s->recv_handler(s->fd, buf, data_len);
    }else if(tcphin->fin){
        struct ip_hdr iph;

        pbuf = pktbuf_alloc2(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        pbuf->data += ETH_HDR_LEN + IP_HDR_LEN;
        pbuf->len += TCP_HDR_LEN;

        tcph = (struct tcp_hdr *)pbuf->data;
        tcph->dport = s->dport;
        tcph->sport = s->sport;
        tcph->hdr_len = 5;
        tcph->seq_num = htonl(s->seq_num);
        tcph->ack_num = htonl(ntohl(tcphin->seq_num) + 1);
        tcph->fin = 1;
        tcph->ack = 1;
        tcph->win = TCP_WIN_SIZE;

        memset(&iph, 0, IP_HDR_LEN);
        iph.proto = IP_PROTO_TCP;
        iph.dst.addr = iphdr(pbufin)->src.addr;

        if(!ip_fill_header(&iph))
            return;

        tcph->checksum = tcp_checksum(&iph, tcph, 20);
        ip_send(pbuf, &iph);

        s->state = TCP_STATE_LAST_ACK;
    }
}

int tcp_recv(struct pktbuf *pbuf){
    struct tcp_hdr *tcph = tcphdr(pbuf);
    struct sock *s;
    struct ip_addr src;
    int data_len;
    char buf[8192];

    pbuf->hdr_offset += TCP_HDR_LEN;

    DBG(("tcp header sport:%u dport:%u seq_num:%u ack_num:%u hdr_len:%u "
         "ack:%u psh:%u rst:%u syn:%u fin:%u win:%u checksum:%04x\n",
         ntohs(tcph->sport), ntohs(tcph->dport), ntohl(tcph->seq_num),
         ntohl(tcph->ack_num), tcph->hdr_len, tcph->ack, tcph->psh,
         tcph->rst, tcph->syn, tcph->fin, ntohs(tcph->win), ntohs(tcph->checksum)));

    src.addr = iphdr(pbuf)->src.addr;
    s = sock_lookup(SOCK_STREAM, NULL, tcph->dport, &src, tcph->sport);

    if(!s && !(s = sock_lookup(SOCK_STREAM, NULL, tcph->dport, NULL, 0))){
        DBG(("no sock found\n"));
        tcp_rst(pbuf);
        pktbuf_free(pbuf);
        return 0;
    }

    DBG(("tcp_recv %p\n", s));

    switch(s->state){
    case TCP_STATE_LISTEN:
        tcp_new_conn(s, pbuf);
        break;
    case TCP_STATE_SYN_RECV:
        tcp_commit_conn(s, pbuf);
        break;
    case TCP_STATE_ESTABLISHED:
        tcp_process_conn(s, pbuf);
        break;
    case TCP_STATE_LAST_ACK:
        if(tcph->ack && ntohl(tcphdr(pbuf)->ack_num) == s->seq_num + 1){
            sock_close(s->fd);
        }
        break;
    default:
        return 0;
    }

    pktbuf_free(pbuf);

    return 0;
}

int tcp_send(struct sock *s, void *buf, int buf_len){
    struct pktbuf *pbuf;
    struct tcp_hdr *tcph;
    struct ip_hdr iph;

    if(buf_len < 1)
        return 0;

    pbuf = pktbuf_alloc2(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + buf_len);
    pbuf->data += ETH_HDR_LEN + IP_HDR_LEN;
    pbuf->len += TCP_HDR_LEN + buf_len;

    tcph = (struct tcp_hdr *)pbuf->data;
    tcph->dport = s->dport;
    tcph->sport = s->sport;
    tcph->hdr_len = 5;
    tcph->seq_num = htonl(s->seq_num);
    tcph->ack_num = htonl(s->ack_num);
    tcph->psh = 1;
    tcph->ack = 1;
    tcph->win = TCP_WIN_SIZE;
    s->seq_num = s->seq_num + buf_len;

    if(buf_len)
        memcpy(pbuf->data + TCP_HDR_LEN, buf, buf_len);

    memset(&iph, 0, IP_HDR_LEN);
    iph.proto = IP_PROTO_TCP;
    iph.dst.addr = s->dst.addr;

    if(!ip_fill_header(&iph))
        return 0;

    tcph->checksum = tcp_checksum(&iph, tcph, TCP_HDR_LEN + buf_len);
    ip_send(pbuf, &iph);
}
