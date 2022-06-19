INCLUDE= -I ./include
LDFLAG= -lpthread 
CFLAGS= -g --std=c11 -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -pthread -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDE)

OBJECTS= ./logger/logger.o ./utils/util.o ./utils/net_utils.o ./selector/selector.o ./stm/stm.o ./managers/socksv5/socksv5_nio.o ./managers/dog_manager/dog.o ./managers/dog_manager/dog_manager.o ./buffer/buffer.o ./parser/socksv5/hello_parser.o  ./parser/socksv5/auth_parser.o ./parser/socksv5/request_parser.o ./parser/pop3_sniffer/pop3_sniffer.o ./statistics/statistics.o ./utils/user_utils.o

all: ${OBJECTS}
	@echo "\n!!!	Making SOCKS5 proxy	!!!\n";
	$(CC) $(CFLAGS) $(LDFLAG) -o ../socks5d main.c args.c $(OBJECTS)
	@echo "\n!!!	Making DOG manager	!!!\n";
	$(CC) $(CFLAGS) $(LDFLAG) -o ../dog ./dog_client/dog_client.c args.c $(OBJECTS)

clean:
	rm -r -f *.o ./parser/*.o ./parser/socksv5/*.o ./utils/*.o ./buffer/*.o ./managers/socksv5/*.o ./managers/dog_manager/*.o ./selector/*.o ./stm/*.o ./statistics/*.o ./parser/pop3_sniffer/*.o ./logger/*.o ./utils/*.o ./dog_client/*.o socks5d dog $(COMMON);

.PHONY: all clean