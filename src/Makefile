INCLUDE = -I ./include
LDFLAG=-lm -lcheck -lrt -lpthread -lsubunit -lm
#TODO: faltan estas dos pero no me dejan compilar -pedantic -std=c11 
CFLAGS=--std=c11 -pedantic -pedantic-errors -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L -lm $(INCLUDE)

UTILS=./logger/logger.o ./net_utils/util.o
SERVER_SOURCES=tcpTransparentServer.o ./net_utils/tcpServerUtil.o ./net_utils/tcpClientUtil.o

#all:main transparent
all: transparent

clean:
	- rm  -f *.o tcpTransparentServer


main: main.c

transparent: $(SERVER_SOURCES) $(UTILS)
	$(CC) $(CFLAGS) -o tcpTransparentServer $(SERVER_SOURCES) $(UTILS)
clean: 
	rm -rf */*.o tcpTransparentServer

.PHONY: clean