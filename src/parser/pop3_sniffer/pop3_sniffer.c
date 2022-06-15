#include <string.h>
#include <ctype.h>
#include "pop3_sniffer.h"

static const char * OK = "+OK";
static const char * USER = "USER ";
static const char * PASS = "PASS ";
static const char * ERR = "-ERR";

static enum pop3_sniffer_state ok_message(struct pop3_sniffer_parser* p, uint8_t byte) {
    if(tolower(byte) == tolower(*(OK + p->read))) {
        p->read_bytes++;
        p->remaining_bytes--;
        if(p->remaining_bytes == 0){
            s->read_bytes = 0;
            s->remaining_bytes = strlen("USER ");
            return POP3_USER;
        }
    }
    else {
        return POP3_TRAP;
    }
    return POP3_OK;
}

enum pop3_sniffer_state user_message(struct pop3_sniffer_parser* p, uint8_t byte) {
    if(tolower(b) == tolower(*(USER + s->read))) {
        p->read_bytes++;
        p->remaining_bytes--;
        if(p->remaining_bytes == 0){
            p->read_bytes = 0;
            return POP3_READ_USER;
        }        
    } else if(p->read_bytes != 0) {
        p->read_bytes = 0;
        p->remaining_bytes = strlen(USER);
    } 
    return POP3_USER;
}

enum pop3_sniffer_state pass_message(struct pop3_sniffer_parser* p, uint8_t byte) {
    if(tolower(b) == tolower(*(PASS + s->read))) {
        p->read_bytes++;
        p->remaining_bytes--;
        if(p->remaining_bytes == 0){
            p->read_bytes = 0;
            return POP3_READ_PASS;
        }        
    } else if(p->read_bytes != 0) {
        p->read_bytes = 0;
        p->remaining_bytes = strlen(PASS);
    } 
    return POP3_PASS;
}


void pop3_sniffer_parser_init(pop3_sniffer_parser *parser) {
    sniffer->current_state = POP3_OK;
}

enum pop3_sniffer_state pop3_sniffer_parser_feed(pop3_sniffer_parser *p, const uint8_t byte) {
    switch (s->current_state) {
        case POP3_OK:
            s->state = ok_message(p, byte);
        break;

        case POP3_USER:
            s->state = user_message(p, byte);
        break;

        case POP3_READ_USER:
            s->state = NULL;
        break;

        case POP3_PASS:
            s->state = pass_message(p, byte);;
        break;

        case POP3_READ_PASS:
            s->state = NULL;
        break;

        case POP3_CHECK:
            s->state = NULL;
        break;    

        case POP3_TRAP:
        case POP3_SUCCESS:
            // Nothing to do
        break;    

        default:
            log_print(DEBUG,"Unknown state on POP3 sniffer parser");
            abort();
        break;
    }
    return s->state;
}

bool pop3_sniffer_parser_is_done(struct pop3_sniffer_parser *p) {
    return s->state == POP3_SUCCESS;
}

enum pop3_sniffer_state pop3_sniffer_parser_consume(struct pop3_sniffer_parser *p) {
    while(buffer_can_read(&p->buffer) && !pop3_sniffer_parser_is_done(p)) {
        uint8_t byte = buffer_read(&p->buffer);
        p->current_state = pop3_sniffer_parser_feed(p, byte);
    }

    if(p->current_state == POP3_SUCCESS) {
        log_print(INFO, "\nSniffed POP3 credentials\n\n");
        log_print(INFO, "Username: %s \n\n", pop3_sniffer_parser->username);
        log_print(INFO, "Password: %s \n\n", pop3_sniffer_parser->password);
    }

    return s->state;
}