CXXFLAGS += -std=c++17
LDLIBS = -lpcap -lnet

arpconfig: arpconfig.cc

install:
	strip arpconfig
	cp arpconfig /usr/local/bin/
