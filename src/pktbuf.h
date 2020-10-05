#ifndef _DELTAIP_PKTBUF_H
#define _DELTAIP_PKTBUF_H
#define PKTBUF_LEN sizeof(struct pktbuf)
#include "iface.h"

struct pktbuf {
    int len;
    int hdr_offset;
    uint8_t *data;
    struct iface *iface;
};

struct pktbuf *pktbuf_alloc(int pad, int hdrlen, int datalen);
void pktbuf_free(struct pktbuf *);
struct pktbuf *pktbuf_alloc2(int len);
int pktbuf_add_header(struct pktbuf *pbuf, int hdrlen);

#endif
