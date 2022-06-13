INCLUDE= -I ./include
LDFLAG= -lm -lcheck -lrt -lpthread -lsubunit

CFLAGS= -g --std=c11 -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -pthread -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDE)

#UTILS=./logger/logger.o ./net_utils/util.o
#SERVER_SOURCES=tcpTransparentServer.o ./net_utils/tcpServerUtil.o ./net_utils/tcpClientUtil.o

OBJECTS= ./logger/logger.o ./net_utils/util.o ./selector/selector.o ./stm/stm.o ./nio/socksv5_nio.o ./buffer/buffer.o ./parser/socksv5/hello_parser.o  ./parser/socksv5/auth_parser.o ./parser/socksv5/request_parser.o
#all:main transparent
#all: transparent
#TODO: LOS LDFLAGS NO ANDAN
all: ${OBJECTS}
	$(CC) $(CFLAGS) -o ../server main.c args.c $(OBJECTS)

clean:
	rm -r -f *.o ./parsers/*.o ./parsers/socksv5/*.o ./net_utils/*.o ./buffer/*.o ./nio/*.o ./selector/*.o ./stm/*.o server $(COMMON);

main: main.c

#transparent: $(SERVER_SOURCES) $(UTILS)
#	$(CC) $(CFLAGS) -o tcpTransparentServer $(SERVER_SOURCES) $(UTILS)
#clean: 
#	rm -rf */*.o tcpTransparentServer

.PHONY: all clean subdirs