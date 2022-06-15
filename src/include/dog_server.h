#ifndef DOG_SERVER_H
#define DOG_SERVER_H

#include "selector.h"

#define BUFFER_SIZE 1024

void manager_passive_accept(struct selector_key *key);

#endif