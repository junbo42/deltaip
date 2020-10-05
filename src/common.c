#include <stdlib.h>  // exit
#include <time.h>   // clock_gettime, need to remove
#include "common.h"
#include "arp.h"
#include "iface.h"
#include "ip.h"
#include "route.h"
#include "sock.h"

unsigned long jiffies;

void print_pkt(uint8_t *data, int size){
    int i;
    for(i = 0; i < size; i++){
        INFO(("%02x ", data[i]));
    }
    INFO(("\n"));
}

void panic(char *msg){
    INFO(("%s\n", msg));
    exit(0);
}

void deltaip_init(){
    iface_init();
    arp_init();
    route_init();
    sock_init();
}

void deltaip_task(){
    DBG(("deltaip_task\n"));
    jiffies = gettime();
    arp_task();
}

long gettime(){
    struct timespec b;
    clock_gettime(CLOCK_MONOTONIC, &b);
    return b.tv_sec;
}

char *ntoa(uint32_t src, char *dst){
    sprintf(dst, "%d.%d.%d.%d", src >> 24 & 0xff, src >> 16 & 0xff,
        src >> 8 & 0xff, src & 0xff);

    return dst;
}

int htohs(uint16_t x){
    return __builtin_bswap16(x);
}

int ntohs(uint16_t x){
    return __builtin_bswap16(x);
}

int htonl(uint32_t x){
    return __builtin_bswap32(x);
}

int ntohl(uint32_t x){
    return __builtin_bswap32(x);
}
