#ifndef POP3_SNIFFER_H
#define POP3_SNIFFER_H

#include <stdint.h>
#include "buffer.h"
#include "logger.h"

#define CREDENTIALS_MAX_LENGTH 256
#define MAX_BUFF_POP3_SIZE 4096

typedef enum pop3_sniffer_state {
    POP3_OK,
    POP3_USER,
    POP3_READ_USER,
    POP3_PASS,
    POP3_READ_PASS,
    POP3_CHECK,  
    POP3_TRAP
    POP3_SUCCESS
} pop3_sniffer_state;


typedef struct pop3_sniffer_parser {

    pop3_sniffer_state current_state;
    bool is_initiated;
    buffer buffer;
    char username[MAX_CREDENTIAL_SIZE];
    char password[MAX_CREDENTIAL_SIZE];
    uint8_t remaining_bytes;
    uint8_t read_bytes;
} pop3_sniffer_parser;

void pop3_sniffer_parser_init(pop3_sniffer_parser *p);

enum pop3_sniffer_state pop3_sniffer_parser_feed(pop3_sniffer_parser *p, const uint8_t byte);

bool pop3_sniffer_parser_is_done(struct pop3_sniffer_parser *p);

enum pop3_sniffer_state pop3_sniffer_parser_consume(struct pop3_sniffer_parser *p);

#endif