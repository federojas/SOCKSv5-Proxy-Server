#ifndef SOCKSV5_NIO_H
#define SOCKSV5_NIO_H

#include <netdb.h>
#include "./selector.h"

#define ADDR_CHAR_SIZE 64

void socksv5_passive_accept(struct selector_key *key);

void socksv5_pool_destroy(void);

#endif


