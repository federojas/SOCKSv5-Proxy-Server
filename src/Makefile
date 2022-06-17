INCLUDE= -I ./include
LDFLAG= -lpthread -pthread
CFLAGS= -g --std=c11 -pedantic  -pedantic-errors  -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -Wno-unused-variable  -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDE)

OBJECTS= ./logger/logger.o ./utils/util.o ./utils/net_utils.o ./selector/selector.o ./stm/stm.o ./managers/socksv5/socksv5_nio.o ./managers/dog_manager/dog.o ./managers/dog_manager/dog_manager.o ./buffer/buffer.o ./parser/socksv5/hello_parser.o  ./parser/socksv5/auth_parser.o ./parser/socksv5/request_parser.o ./parser/pop3_sniffer/pop3_sniffer.o ./statistics/statistics.o ./utils/user_utils.o


		
all:socks5d
 
	

clean:
	rm -r -f *.o ./parser/*.o ./parser/socksv5/*.o ./net_utils/*.o ./buffer/*.o ./nio/*.o ./selector/*.o ./stm/*.o ./statistics/*.o ./parser/pop3_sniffer/*.o ./logger/logger.o  $(OBJECTS);

socks5d:  ${OBJECTS} 
	@echo  "\n+-----	armando proxy socksv5	-----+\n";
	$(CC) $(LDFLAG) $(CFLAGS) -o ../socks5d main.c args.c $(OBJECTS)
	@echo  "\n+--------------------------------------+\n";

.PHONY: all clean