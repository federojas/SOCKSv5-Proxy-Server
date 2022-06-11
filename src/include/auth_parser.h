/*  Parser para socks5 authentication
*
*
*/
#ifndef AUTH_PARSER_H
#define AUTH_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "buffer.h"

#define CHAR_MAX_LENGTH 256

typedef enum auth_parser_state {
    AUTH_VERSION,
    AUTH_USERNAME_LEN,
    AUTH_USERNAME,
    AUTH_PASSWORD_LEN,
    AUTH_PASSWORD,
    AUTH_DONE,
    AUTH_TRAP,
} auth_parser_state;

typedef enum auth_trap_cause {
    AUTH_VALID,
    AUTH_INVALID_VERSION,
    AUTH_INVALID_USERNAME_LEN,
    AUTH_INVALID_PASSWORD_LEN,
} auth_trap_cause;

typedef struct auth_parser {

    uint8_t version;
    uint8_t username_len;
    char username[CHAR_MAX_LENGTH];
    uint8_t password_len;
    char password[CHAR_MAX_LENGTH];
    uint8_t credentials_pointer;

    auth_parser_state current_state;
    auth_trap_cause trap_cause;
} auth_parser;

void auth_parser_init(auth_parser *p);

enum auth_parser_state auth_parser_feed(auth_parser *p, const uint8_t byte);

bool auth_parser_consume(buffer *buffer, auth_parser *p, bool *errored);

bool auth_parser_is_done(enum auth_parser_state state, bool *errored);

char * auth_parser_error_report(enum auth_trap_cause error_cause);

#endif