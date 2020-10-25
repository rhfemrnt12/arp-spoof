LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

main.o: main.cpp libnet-headers.h
	g++ -c -Wall -o main.o main.cpp -lpcap
clean:
	rm -f send-arp-test *.o
