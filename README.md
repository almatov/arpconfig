# arpconfig utility

This is a C++ written utility that use ARP information to configure interface
with the free IP address in the internal wire network. It tries to predict
ARP values by listening to incoming packets. When unsuccessful, it tries to
provocate ARP requests. The utility uses a predicted MAC address or generates
a random MAC address of a popular vendor. The utility was compiled and tested
under the Armbian Linux. But it should be work under any other Linux system.
The utility uses the ip command to configure interface.

## How to install

Software requirements:

	g++-6.3.0+	(apt install build-essential)
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
