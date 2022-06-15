#ifndef DOG_NIO_H
#define DOG_NIO_H

#include "selector.h"

#define BUFFER_SIZE 1024

void manager_passive_accept(struct selector_key *key);

#endif