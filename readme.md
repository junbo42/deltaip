
# DeltaIP

DeltaIP is a simple tcpip implementation.

It's not finished yet, but should works fine for testing.

# Run it on linux

git clone https://github.com/junbo42/deltaip

cd deltaip/src

make

ip tuntap add deltaip mode tap

brctl addif br0 deltaip

ip link set deltaip up

ip address add 10.4.4.1/24 dev br0

./echoserver

echoserver is a server program that listen on tcp 10.4.4.101:4000 and udp 10.4.4.101:4000 port, send back everything it received.
