#!/bin/bash  
IP_ADDRESS=192.168.191.128
IP_ADDRESS_MAIN=192.168.191.129
IP_ADDRESS_NS=192.168.191.130

NETWORK_INTERFACE=ens33
NAMESPACE=test
sudo ip netns add $NAMESPACE
sudo ip link add type veth
sudo ip link set veth1 netns $NAMESPACE
sudo ip addr add $IP_ADDRESS_MAIN/24 dev veth0
sudo ip link set dev veth0 up
sudo ip netns exec $NAMESPACE ip addr add $IP_ADDRESS_NS/24 dev veth1
sudo ip netns exec $NAMESPACE ip link set dev veth1 up
sudo ip netns exec $NAMESPACE ip ro add default via $IP_ADDRESS_MAIN
sudo ip netns exec $NAMESPACE ifconfig lo 127.0.0.1 netmask 255.0.0.0 up
sudo iptables -A POSTROUTING -t nat -o $NETWORK_INTERFACE -s $IP_ADDRESS_NS -j MASQUERADE
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# If DNS queries are not answered -> install resolvconf and execute following commands
# cd /etc/resolvconf/resolv.conf.d
# sudo cp -p head head.orig  #backup copy, always do this
# sudo nano head
# nameserver <ip_of_nameserver>
# sudo resolvconf -u


# start process in namespace
# # ip netns exec <NSNAME> bash
# su <userid>
# $ firefox &


#### Alternative non working way on desktop with wired network connection

# sudo ip link add veth-a type veth peer name veth-b
# sudo ip link set veth-a netns $NAMESPACE
# sudo ip netns exec $NAMESPACE ifconfig veth-a up 192.168.163.1 netmask 255.255.255.0
# sudo ip netns exec $NAMESPACE ifconfig lo 127.0.0.1 netmask 255.0.0.0 up

# sudo ifconfig veth-b up 192.168.163.254 netmask 255.255.255.0
# ##ALTERNATIVE? ip netns exex test ip ro add default via 192.168.191.128

# sudo ip netns exec $NAMESPACE route add default gw 192.168.163.254 dev veth-a
# sudo iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o $NETWORK_INTERFACE -j SNAT --to-source $IP_ADDRESS;




