all: 
	cd src; make all		

clean:
	rm -r -f *.o socks5d;	
	cd src; make clean
	cd test; make clean
	cd src;

.PHONY: all clean
