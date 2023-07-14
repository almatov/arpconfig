# arpconfig utility

This is a C++ writtten utility that helps to obtain IP address when the network has no DHCP/BOOTP server. The program can be started simultaneously with DHCP client and then can be killed on the exit hook.

The utility analizes incoming packets to find free IP address. It can use ARP requests to predict unused IP addresses. Then the utility changes MAC and IP addresses on the interface according found ARP information.

This utility was compiled and tested in Armbian Linux, but it should work in any other Linux system. This utility uses the ip command to configure the interface.

## How to install

Software requirements:

	g++-6.3.0+      (apt install build-essential)
	libpcap-1.8.1+ 	(apt install libpcap-dev)
	libnet-1.1.6+ 	(apt install libnet1-dev)

Run this

	make
	sudo make install

## How to use

Configure interface eth0

	sudo arpconfig -e eth0

Just test and print configuration commands

	sudo arpconfig eth0

Print help message

	arpconfig -h
