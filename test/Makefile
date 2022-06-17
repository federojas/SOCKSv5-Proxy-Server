INCLUDE = -I ../src/include

LIBRARIES=-lm -lcheck -lrt -lpthread -lsubunit
CFLAGS= -g --std=c11 -fsanitize=address -Wall -Wextra -Werror -Wno-unused-parameter -pthread -Wno-implicit-fallthrough -D_POSIX_C_SOURCE=200112L $(INCLUDE)

BUFFER_TEST=./tests/buffer_test.o ../src/buffer/buffer.o

tests: buffer_test 

buffer_test: $(BUFFER_TEST)

	$(CC) $(CFLAGS) -o ./buffer_test ./tests/buffer_test.c  ../src/buffer/buffer.c $(BUFFER_TEST)
	
all: main
main:buffer_test

clean: 
	rm -rf */*.o

.PHONY: all clean

