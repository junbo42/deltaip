#include "stdlib.h"
#include "sock.h"
#include "udp.h"
#include "tcp.h"

static unsigned int sockfd;
static unsigned int sock_count;

static struct sock *sock_base, *sock_last;

void sock_init(){
    sock_base = NULL;
}

int sock_create(int domain, int type, int protocol){
    struct sock *s;

    if(sock_count > SOCK_MAX){
        INFO(("socket table is full\n"));
        return -1;
    }

    s = malloc(sizeof(struct sock));
    memset(s, 0, sizeof(struct sock));
    //s->domain = domain;
    s->type = type;
    s->fd = sockfd;
    //s->rbuf = malloc(SOCK_BUF_SIZE);
    //s->wbuf = malloc(SOCK_BUF_SIZE);

    switch(type){
    case SOCK_DGRAM:
        s->ops = &udp_ops;
        break;
    case SOCK_STREAM:
        s->ops = &tcp_ops;
        s->state = TCP_STATE_LISTEN;
        break;
    default:
        INFO(("unknow socket type %d\n", type));
        return -1;
    }

    if(sock_last){
        sock_last->next = s;
        sock_last = s;
    }else{
        sock_base = sock_last = s;
    }

    sock_count++;
    sockfd++;
    return s->fd;
}

int deltaip_socket(int domain, int type, int protocol){
    if(domain != AF_INET){
        INFO(("only ipv4 supported\n"));
    }
    return sock_create(domain, type, protocol);
}

int deltaip_bind(int socket, int port){
    struct sock *s;
    int found = 0;

    SOCK_FOREACH(s){
        if(s->fd == socket){
            found = 1;
            break;
        }
    }

    if(!found)
        return -1;

    s->sport = port;

    return 0;
}

int deltaip_register_recvfrom_handler(int sockfd, int (*handler)(void *buf,
        int buf_len, struct ip_addr *dst, int port)){
    struct sock *s;

    if(!(s = sock_lookup_fd(sockfd)))
        return -1;

    s->recvfrom_handler = handler;
}

int deltaip_register_recv_handler(int sockfd, int (*handler)(int, void *, int)){
    struct sock *s;

    if(!(s = sock_lookup_fd(sockfd)))
        return -1;

    s->recv_handler = handler;
}

int deltaip_sendto(int sockfd, void *buf, int buf_len,
        struct ip_addr *dst, int port){
    struct sock *s;
    
    if(!(s = sock_lookup_fd(sockfd)))
        return -1;

    s->ops->sendto(s, buf, buf_len, dst, port);
}

int deltaip_send(int sockfd, void *buf, int buf_len){
    struct sock *s;
    
    if(!(s = sock_lookup_fd(sockfd)))
        return -1;

    if(s->type != SOCK_STREAM)
        return -1;

    s->ops->send(s, buf, buf_len);
}


struct sock *sock_lookup_fd(int sockfd){
    struct sock *s;

    SOCK_FOREACH(s){
        if(s->fd == sockfd){
            return s;
        }
    }

    return NULL;
}

struct sock *sock_lookup(int type, struct ip_addr *src, int sport, struct ip_addr *dst, int dport){
    struct sock *s;

    SOCK_FOREACH(s){
        if(!(s->type == type && s->sport == sport && s->dport == dport))
            continue;
        if(src && !(s->src.addr == src->addr))
            continue;
        if(dst && !(s->dst.addr == dst->addr))
            continue;
        return s;
    }

    return NULL;
}

void sock_close(int sockfd){
    struct sock *s, *prev;
    int found;

    SOCK_FOREACH(s){
        if(s->fd == sockfd){
            found = 1;
            break;
        }
        prev = s;
    }

    if(!found)
        return;

    if(prev){
        prev->next = s->next;
    }else{
        sock_base = NULL;
    }
    if(sock_last == s)
        sock_last = prev;

    free(s);
}
