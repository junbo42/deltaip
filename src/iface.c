#include "common.h"
#include "iface.h"
#include "route.h"

struct iface *iface_base;

void iface_init() {
    iface_base = NULL;
}

struct iface *iface_add(char *name, uint8_t *mac){
    struct iface *ifa, *ifc;

    for(ifa = iface_base; ifa != NULL; ifa = ifa->next){
        if(!strcmp(ifa->name, name))
            return NULL;
    }

    ifc = malloc(sizeof(struct iface));
    strcpy(ifc->name, name);
    memcpy(ifc->eth_addr.addr, mac, 6);

    if(!iface_base) {
        iface_base = ifc;
    } else {
        ifa->next = ifc;
    }
    return ifc;
}

void iface_del(char *name) {
    struct iface *ifa, *prev;

    for(ifa = iface_base; ifa != NULL; ifa = ifa->next){
        if(!strcmp(ifa->name, name)){
            prev->next = ifa->next;
            free(ifa);
            break;
        }
        prev = ifa;
    }

    //TODO delete route also!
}

struct iface *iface_lookup(char *name) {
    struct iface *ifa, *prev;

    for(ifa = iface_base; ifa != NULL; ifa = ifa->next){
        if(!strcmp(ifa->name, name))
            return ifa;
    }

    return NULL;
}

void iface_print() {
    struct iface *ifa;
    struct eth_addr *mac;

    for(ifa = iface_base; ifa != NULL; ifa = ifa->next){
        PRINT(("%s %02x:%02x:%02x:%02x:%02x:%02x\n", ifa->name, ifa->eth_addr.addr[0],
            ifa->eth_addr.addr[1], ifa->eth_addr.addr[2], ifa->eth_addr.addr[3], ifa->eth_addr.addr[4],
            ifa->eth_addr.addr[5]));
    }
}

void iface_ip_add(char *name, uint32_t ip, uint32_t mask) {
    struct iface *ifa;
    struct ipaddr *ipaddr;
    int maxip = 8;

    IFACE_FOREACH(ifa){
        if(!strcmp(ifa->name, name))
            break;
        return;
    }

    ipaddr = ifa->ipaddr;
    while(ipaddr->ip.addr){
        if(!maxip)
            return;
        maxip--;
        ipaddr++;
    }

    ipaddr->ip.addr = htonl(ip);
    ipaddr->mask = mask;

    route_add(ip, mask, ifa, 0);
}

void iface_ip_print(struct iface *ifa) {
    struct ipaddr *ipaddr = ifa->ipaddr;
    char buf1[32];
    char buf2[32];

    while(ipaddr->ip.addr){
        PRINT(("%s %s %s\n", ifa->name, ntoa(ntohl(ipaddr->ip.addr), buf1), ntoa(ipaddr->mask, buf2)));
        ipaddr++;
    }
}
