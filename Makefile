all: 
	cd src; make all

test: 
	cd test; make all		

clean:
	cd src; make clean
	cd test; make clean

.PHONY: test all clean
