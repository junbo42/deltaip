CC = cc
CFLAGS += -g

all: libdeltaip echoserver

echoserver: echoserver.c libdeltaip
	${CC} echoserver.c tap.c -o echoserver ${CFLAGS} -I. -L. -ldeltaip

libdeltaip: common pktbuf ether arp ip icmp udp route iface sock tcp
	ar rcs libdeltaip.a common.o arp.o ether.o ip.o pktbuf.o icmp.o udp.o tcp.o route.o iface.o sock.o

common: common.c
	${CC} -c -o common.o common.c ${CFLAGS}

pktbuf: pktbuf.c
	${CC} -c -o pktbuf.o pktbuf.c ${CFLAGS}

ether: ether.c
	${CC} -c -o ether.o ether.c ${CFLAGS}

arp: arp.c
	${CC} -c -o arp.o arp.c ${CFLAGS}

ip: ip.c
	${CC} -c -o ip.o ip.c ${CFLAGS}

icmp: icmp.c
	${CC} -c -o icmp.o icmp.c ${CFLAGS}

udp: udp.c
	${CC} -c -o udp.o udp.c ${CFLAGS}

tcp: tcp.c
	${CC} -c -o tcp.o tcp.c ${CFLAGS}

route: route.c
	${CC} -c -o route.o route.c ${CFLAGS}

iface: iface.c
	${CC} -c -o iface.o iface.c ${CFLAGS}

sock: sock.c
	${CC} -c -o sock.o sock.c ${CFLAGS}

clean:
	rm -f *.o *.a echoserver
