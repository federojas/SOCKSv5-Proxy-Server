all: 
	cd src; make all		

clean:
	rm -r -f *.o socks5d dog;	
	cd src; make clean

.PHONY: all clean
