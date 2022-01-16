CXXFLAGS += -std=c++17
LDLIBS = -lpcap -lnet

arpconfig: arpconfig.cc

install:
	cp arpconfig /usr/local/bin/
