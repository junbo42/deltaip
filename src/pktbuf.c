#include "common.h"
#include "pktbuf.h"

struct pktbuf *pktbuf_alloc(int pad, int hdrlen, int datalen){
    struct pktbuf *pbuf = malloc(pad + hdrlen + datalen);

    if(pbuf == NULL){
        panic("failed to allocate pktbuf");
    }

    memset(pbuf, 0, pad + hdrlen + datalen);

    if(hdrlen){
        pbuf->data = (uint8_t *)pbuf + PKTBUF_PAD;
        pbuf->len = hdrlen;
    } else {
        pbuf->data = (uint8_t *)pbuf + PKTBUF_LEN;
    }

    return pbuf;
}

void pktbuf_free(struct pktbuf *pbuf){
    if(pbuf)
        free(pbuf);
}

struct pktbuf *pktbuf_alloc2(int len){
    struct pktbuf *pbuf = malloc(len + PKTBUF_LEN);

    if(pbuf == NULL){
        panic("failed to allocate pktbuf");
    }

    memset(pbuf, 0, len + PKTBUF_LEN);
    pbuf->data = (uint8_t *)pbuf + PKTBUF_LEN;

    return pbuf;
}

int pktbuf_add_header(struct pktbuf *pbuf, int hdrlen){
    pbuf->data = pbuf->data - hdrlen;
    pbuf->len += hdrlen;
}
