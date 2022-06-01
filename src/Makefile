INCLUDE = -I ./include
CC=gcc
LIBRARIES=-lm -lcheck -lrt -lpthread -lsubunit
#TODO: faltan estas dos pero no me dejan compilar -pedantic -std=c11 
CFLAGS=-Wall  -g -pthread -fsanitize=address $(INCLUDE)
UTILS=./logger/logger.c ./net_utils/util.c
all: main transparent

main: main.c

transparent: 
	$(CC) $(CFLAGS) -o tcpTransparentServer tcpTransparentServer.c ./net_utils/tcpServerUtil.c ./net_utils/tcpClientUtil.c $(UTILS)
clean: 
	rm -rf */*.o tcpTransparentServer

.PHONY: clean