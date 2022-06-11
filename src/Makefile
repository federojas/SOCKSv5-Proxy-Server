INCLUDE= -I ./include
LDFLAG= -lm -lcheck -lrt -lpthread -lsubunit

CFLAGS= -g --std=c11 -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDE)

#UTILS=./logger/logger.o ./net_utils/util.o
#SERVER_SOURCES=tcpTransparentServer.o ./net_utils/tcpServerUtil.o ./net_utils/tcpClientUtil.o

OBJECTS= ./logger/logger.o ./net_utils/util.o ./selector/selector.o

#all:main transparent
#all: transparent
all: ${OBJECTS}
	$(CC) $(CFLAGS) -o server main.c $(OBJECTS)

clean: -rm  -f *.o ./selector/*.o ./logger/*.o ./net_utils/*.o 


main: main.c

#transparent: $(SERVER_SOURCES) $(UTILS)
#	$(CC) $(CFLAGS) -o tcpTransparentServer $(SERVER_SOURCES) $(UTILS)
#clean: 
#	rm -rf */*.o tcpTransparentServer

.PHONY: clean