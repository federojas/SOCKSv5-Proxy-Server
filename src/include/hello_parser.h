/*  Parser para el handshake de socks5
*
*
*/
#ifndef HELLO_PARSER_H
#define HELLO_PARSER_H
#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

static const uint8_t METHOD_NO_AUTH_REQ = 0x00;
static const uint8_t METHOD_AUTH_REQ = 0x02;

static const uint8_t METHOD_NO_ACCEPTABLE_METHODS = 0xFF;

enum hello_parser_state {
    HELLO_VERSION,
    HELLO_NMETHODS,
    HELLO_METHODS,
    HELLO_DONE,
    HELLO_TRAP,
};

typedef struct hello_parser {
    void (*on_auth_method)(struct hello_parser *parser, uint8_t method);
    void *data;
    enum hello_parser_state current_state;
    uint8_t methods_remaining;
} hello_parser;

void hello_parser_init(hello_parser *p, void (*on_auth_method)(hello_parser *p, uint8_t method));

enum hello_parser_state hello_parser_feed(hello_parser *p, const uint8_t byte);

bool hello_parser_consume(buffer *b, hello_parser *p, bool *errored);

bool hello_parser_is_done(enum hello_parser_state state, bool *errored);

char *hello_parser_error_report(enum hello_parser_state state);

char hello_parser_marshall(buffer *b, const uint8_t method);

#endif