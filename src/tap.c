#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>
#include "common.h"
#include "pktbuf.h"
#include "ether.h"
#include "route.h"
#include "iface.h"
#define DEVTAP "/dev/net/tun"

static void port_process(struct iface *ifa){
    int size;

    struct pktbuf *pbuf = pktbuf_alloc2(65536);

    size = read(ifa->fd, pbuf->data, 65536);

    if(size < 0){
        panic("read tap device error");
    }

    pbuf->len = size;
    pbuf->iface = ifa;
    //print_pkt(pbuf->data, size);
    eth_recv(pbuf);
}

void run(){
    int tapfd;

    tapfd = open(DEVTAP, O_RDWR);
    if(tapfd < 0){
        printf("failed to open %s", DEVTAP);
        goto err;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));

    strncpy(ifr.ifr_name, "deltaip", sizeof(ifr.ifr_name));
    ifr.ifr_flags = IFF_TAP|IFF_NO_PI;

    if (ioctl(tapfd, TUNSETIFF, (void *) &ifr) < 0) {
        printf("ioctl TUNSETIFF failed\n");
        goto err;
    }

    struct iface *ifa;
    uint8_t iface1_mac[6] = {0x52, 0x54, 0x00, 0x00, 0x00, 0x01};
    ifa = iface_add("iface1", iface1_mac);
    iface_ip_add("iface1", 168035429, 4294967040);
    iface_ip_add("iface1", 168035430, 4294967040);
    ifa->fd = tapfd;
 
    printf("--- interface\n");
    iface_print();
 
    printf("--- ip address\n");
    iface_ip_print(iface_lookup("iface1"));
 
    route_add(0, 0, NULL, 168035329);
    printf("--- routing table\n");
    route_print();

    printf("\n");

    struct timeval timeout;
    fd_set readfd;
    int rv;

    while(1){
        FD_ZERO(&readfd);
        FD_SET(ifa->fd, &readfd);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        rv = select(tapfd + 1, &readfd, NULL, NULL, &timeout);

        if(rv == -1){
            printf("select error\n");
            goto err;
        }

        if(rv == 0){
            deltaip_task();
            continue;
        }

        if(FD_ISSET(ifa->fd, &readfd))
            port_process(ifa);
    }

err:
    return;
}
