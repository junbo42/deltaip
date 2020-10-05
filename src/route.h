#ifndef _DELTAIP_ROUTE_H
#define _DELTAIP_ROUTE_H
#define ROUTE_FOREACH(entry) FOREACH(route_base, entry)
#include "common.h"

struct route {
    struct route *next;
    uint32_t dst;
    uint32_t mask;
    struct ip_addr gw;
    struct iface *iface;
};

void route_init();

void route_add(uint32_t dst, uint32_t mask, struct iface *ifa, uint32_t gw);

void route_del(uint32_t dst, uint32_t mask);

struct route *route_lookup(uint32_t dst);

extern struct route *route_base;

void route_print();

#endif
