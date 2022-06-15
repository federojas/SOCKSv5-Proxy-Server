INCLUDE= -I ./include
LDFLAG= -lm -lcheck -lrt -lpthread -lsubunit
CFLAGS= -g --std=c11 -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -pthread -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDE)
OBJECTS= ./logger/logger.o ./net_utils/util.o ./selector/selector.o ./stm/stm.o ./nio/socksv5_nio.o ./buffer/buffer.o ./parser/socksv5/hello_parser.o  ./parser/socksv5/auth_parser.o ./parser/socksv5/request_parser.o ./net_utils/netutils.o ./parser/pop3_sniffer/pop3_sniffer.o 

all: ${OBJECTS}
	$(CC) $(CFLAGS) -o ../socks5d main.c args.c $(OBJECTS)

clean:
	rm -r -f *.o ./parser/*.o ./parser/socksv5/*.o ./net_utils/*.o ./buffer/*.o ./nio/*.o ./selector/*.o ./stm/*.o socks5d $(COMMON);

.PHONY: all clean