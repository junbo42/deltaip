#include "sock.h"

void run();

static int udp_fd;
static int tcp_fd;

int udp_handler(void *buf, int buf_len, struct ip_addr *from, int port){
    deltaip_sendto(udp_fd, buf, buf_len, from, port);
}

int tcp_handler(int fd, void *buf, int buf_len){
    deltaip_send(fd, buf, buf_len);
}

void udp_echo_init(){
    char buf[8192];

    udp_fd = deltaip_socket(AF_INET, SOCK_DGRAM, 0);
    deltaip_bind(udp_fd, htons(4000));
    deltaip_register_recvfrom_handler(udp_fd, udp_handler);
}

void tcp_echo_init(){
    char buf[8192];

    tcp_fd = deltaip_socket(AF_INET, SOCK_STREAM, 0);
    deltaip_bind(tcp_fd, htons(4000));
    deltaip_register_recv_handler(tcp_fd, tcp_handler);
}

int main(int argc, char *argv[])
{
    udp_echo_init();
    tcp_echo_init();
    run();
}
