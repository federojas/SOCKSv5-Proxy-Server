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
#define AUTH_SUCCESS 0x00
#define AUTH_FAIL 0x01
#define AUTH_BAD_CREDENTIALS 0x02
#define AUTH_VERSION_ID 0x01

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

typedef struct username {
    uint8_t username_len;
    char username[CHAR_MAX_LENGTH];
} username;

typedef struct password {
    uint8_t password_len;
    char password[CHAR_MAX_LENGTH];
} password;

typedef struct auth_parser {

    uint8_t version;
    struct username username;
    struct password password;
    uint8_t credentials_pointer;

    auth_parser_state current_state;
    auth_trap_cause trap_cause;
} auth_parser;

void auth_parser_init(auth_parser *p);

enum auth_parser_state auth_parser_feed(auth_parser *p, const uint8_t byte);

bool auth_parser_consume(buffer *buffer, auth_parser *p, bool *errored);

bool auth_parser_is_done(enum auth_parser_state state, bool *errored);

char * auth_parser_error_report(enum auth_trap_cause error_cause);

int auth_marshall(buffer *b, const uint8_t status, uint8_t version);

#endif