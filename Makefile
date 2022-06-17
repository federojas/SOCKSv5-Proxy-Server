all: 
	cd src; make all

test: 
	cd test; make all		

clean:
	rm -r -f *.o socks5d;	
	cd src; make clean
	cd test; make clean
	cd src;

.PHONY: test all clean
