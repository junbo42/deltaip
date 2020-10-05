#include "stdlib.h"
#include "common.h"
#include "route.h"
#include "iface.h"

struct route *route_base;

void route_init(){
    route_base = NULL;
}

void route_add(uint32_t dst, uint32_t mask, struct iface *ifa, uint32_t gw){
    struct route *r, *new, *prev, *gwr;
    struct iface *gwif = NULL;

    ROUTE_FOREACH(r){
        if(r->dst == (dst & mask) && r->mask == mask){
            return;
        }
        prev = r;
    }

    new = malloc(sizeof(struct route));
    new->dst = dst & mask;
    new->mask = mask;
    new->gw.addr = gw;

    if(!ifa){
        if(!(gwr = route_lookup(gw)))
            return;
        new->iface = gwr->iface;
    } else {
        new->iface = ifa;
    }

    new->next = NULL;

    if(prev)
        prev->next = new;
    else
        route_base = new;

}

void route_del(uint32_t dst, uint32_t mask){
    struct route *r, *prev;

    ROUTE_FOREACH(r){
        if(r->dst == dst && r->mask == mask){
            if(!prev){
                route_base = NULL;
            } else {
                prev->next = r->next;
            }
            free(r);
            break;
        }
        prev = r;
    }
}

struct route *route_lookup(uint32_t dst){
    struct route *r;

    ROUTE_FOREACH(r)
        if(!(r->dst ^ dst & r->mask))
            return r;
}

void route_print(){
    struct route *r;
    char buf1[32];
    char buf2[32];
    char buf3[32];

    for(r = route_base; r != NULL; r = r->next){
        INFO(("%s %s %s\n", ntoa(r->dst, buf1), ntoa(r->mask, buf2),
              ntoa(r->gw.addr, buf3), r->iface->name));
    }
}
