#include <string.h>
#include <ctype.h>
#include "pop3_sniffer.h"

static const char * OK = "+OK";
static const char * USER = "USER ";
static const char * PASS = "PASS ";
static const char * ERR = "-ERR";

static enum pop3_sniffer_state ok_message(struct pop3_sniffer_parser* p, uint8_t byte) {
    if(tolower(byte) == tolower(*(OK + p->read_bytes))) {
        p->read_bytes++;
        p->remaining_bytes--;
        if(p->remaining_bytes == 0){
            p->read_bytes = 0;
            p->remaining_bytes = strlen("USER ");
            return POP3_USER;
        }
    }
    else {
        return POP3_TRAP;
    }
    return POP3_OK;
}

enum pop3_sniffer_state user_message(struct pop3_sniffer_parser* p, uint8_t byte) {
    if(tolower(byte) == tolower(*(USER + p->read_bytes))) {
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
    if(tolower(byte) == tolower(*(PASS + p->read_bytes))) {
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

enum pop3_sniffer_state read_username(struct pop3_sniffer_parser* p, uint8_t byte){
    if(byte != '\n') {
        if(p->read_bytes < CREDENTIALS_MAX_LENGTH){
            p->username[p->read_bytes++] = byte;
        } else {
            log_print(LOG_ERROR, "Invalid POP3 credentials, max size is 255.");
        }
    } else {
        p->username[p->read_bytes] = '\0';
        p->read_bytes = 0;
        p->remaining_bytes = strlen(PASS);
        return POP3_PASS;
    }
    return POP3_READ_USER;
}

enum pop3_sniffer_state read_password(struct pop3_sniffer_parser* p, uint8_t byte){
    if(byte != '\n') {
        if(p->read_bytes < CREDENTIALS_MAX_LENGTH){
            p->password[p->read_bytes++] = byte;
        } else {
            log_print(LOG_ERROR, "Invalid POP3 credentials, max size is 255.");
        }
    } else {
        p->password[p->read_bytes] = '\0';
        p->read_bytes = 0;
        return POP3_CHECK_OK; 
    }
    return POP3_READ_PASS;
}

enum pop3_sniffer_state check_ok(struct pop3_sniffer_parser* p, uint8_t byte) {
    if(tolower(byte) == tolower(*(OK + p->read_bytes))) {
        p->read_bytes++;
        if(p->read_bytes == strlen(OK))
            return POP3_SUCCESS;
    } else if(tolower(byte) == tolower(*(ERR + p->read_bytes))) {
        p->read_bytes++;
        if(p->read_bytes == strlen(ERR))
            return POP3_USER;
    }
    return POP3_CHECK_OK;
}


void pop3_sniffer_parser_init(pop3_sniffer_parser * p) {
    p->current_state = POP3_OK;
    p->read_bytes = 0;
    p->remaining_bytes = strlen(OK);
    p->is_initiated = true;
}

enum pop3_sniffer_state pop3_sniffer_parser_feed(pop3_sniffer_parser *p, const uint8_t byte) {
    switch (p->current_state) {
        case POP3_OK:
            p->current_state = ok_message(p, byte);
        break;

        case POP3_USER:
            p->current_state = user_message(p, byte);
        break;

        case POP3_READ_USER:
            p->current_state = read_username(p, byte);
        break;

        case POP3_PASS:
            p->current_state = pass_message(p, byte);;
        break;

        case POP3_READ_PASS:
            p->current_state = read_password(p, byte);
        break;

        case POP3_CHECK_OK:
            p->current_state = check_ok(p, byte);
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
    return p->current_state;
}

bool pop3_sniffer_parser_is_done(struct pop3_sniffer_parser *p) {
    return p->current_state == POP3_SUCCESS;
}

enum pop3_sniffer_state pop3_sniffer_parser_consume(struct pop3_sniffer_parser *p) {
    fprintf(stderr,"entre al consume");
    while(buffer_can_read(&p->buffer) && !pop3_sniffer_parser_is_done(p)) {
        uint8_t byte = buffer_read(&p->buffer);
        p->current_state = pop3_sniffer_parser_feed(p, byte);
    }

    if(p->current_state == POP3_SUCCESS) {
        log_print(INFO, "\nSniffed POP3 credentials\n\n");
        log_print(INFO, "Username: %s \n\n", p->username);
        log_print(INFO, "Password: %s \n\n", p->password);
    }

    return p->current_state;
}