#ifndef _DELTAIP_IFACE_H
#define _DELTAIP_IFACE_H
#define IFACE_FOREACH(entry) FOREACH(iface_base, entry)
#include "common.h"

struct ipaddr {
    struct ip_addr ip;
    uint32_t mask;
};

struct iface {
    struct iface *next;
    uint8_t name[128];
    struct eth_addr eth_addr;
    struct ipaddr ipaddr[8];
    int fd;
};

void iface_init();

struct iface *iface_add(char *name, uint8_t *mac);

void iface_del(char *name);

struct iface *iface_lookup(char *name);

void iface_print();

void iface_ip_add(char *name, uint32_t ip, uint32_t mask);

void iface_ip_print(struct iface *ifa);

extern struct iface *iface_base;

#endif
