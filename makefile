LDLIBS=-lpcap

all: tcp-block

main.o: tcphdr.h ethhdr.h iphdr.h ip.h mac.h main.cpp 

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: iphdr.h iphdr.cpp

ip.o: ip.h ip.cpp

mac.o: mac.h mac.cpp

tcp-block: main.o ip.o mac.o iphdr.o ethhdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o
