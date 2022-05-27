INCLUDE = -I ./include

CC=gcc
LIBRARIES=-lm -lcheck -lrt -lpthread -lsubunit
CFLAGS=-Wall -pedantic -std=c11 -g -pthread -fsanitize=address $(INCLUDE)

all: main

main: main.c

clean: 
	rm -rf */*.o

.PHONY: clean