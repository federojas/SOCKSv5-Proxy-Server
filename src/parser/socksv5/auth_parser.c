#include "auth_parser.h"
#include "logger.h"

void auth_parser_init(auth_parser *p) {
    p->trap_cause = AUTH_VALID;
    p->current_state = AUTH_VERSION;
}

enum auth_parser_state auth_parser_feed(auth_parser *p, const uint8_t byte) {
    switch(p->current_state) {
        case AUTH_VERSION:
            if(byte == AUTH_VERSION) {
                p->current_state = AUTH_USERNAME_LEN;
                p->version = byte;
            }    
            else {
                p->current_state = AUTH_TRAP;
                p->error_cause = AUTH_INVALID_VERSION;
            }
        break;
        case AUTH_USERNAME_LEN:
            if(byte < 1) {
                p->error_cause = AUTH_INVALID_USERNAME_LEN
                p->current_state = AUTH_TRAP;
            } else {
                p->username_len = byte;
                p->credentials_pointer = 0;
                p->current_state = AUTH_USERNAME;
            }
        break; 
        case AUTH_USERNAME:
            p->username[p->credentials_pointer++] = (char) byte;
            if(p->credentials_pointer == p->username_len) {
                p->username[p->credentialCharPointer] = 0;
                p->current_state = AUTH_PASSWORD_LEN;
            }
        break; 
        case AUTH_PASSWORD_LEN:
            if(byte < 1) {
                p->error_cause = AUTH_INVALID_PASSWORD_LEN
                p->current_state = AUTH_TRAP;
            } else {
                p->password_len = byte;
                p->credentials_pointer = 0;
                p->current_state = AUTH_PASSWORD;
            }
        break; 
        case AUTH_PASSWORD:
            p->password[p->credentials_pointer++] = (char) byte;
            if(p->credentials_pointer == p->password_len) {
                p->password[p->credentials_pointer] = 0;
                p->current_state = AUTH_DONE;
            }
        break;
    }
    return p->current_state;
}

bool auth_parser_consume(buffer *buffer, auth_parser *p, bool *errored) {
    uint8_t byte;

    while(!auth_parser_is_done(p->current_state, errored) && buffer_can_read(buffer)) {
        byte = buffer_read(buffer);
        auth_parser_feed(p, byte); 
    }

    return auth_parser_is_done(p->current_state, errored);
}

bool auth_parser_is_done(enum auth_parser_state state, bool *errored) {
    if(errored != NULL) {
        if(state == AUTH_TRAP)
            *errored = true;
        else
            *errored = false;
    }
    if(state == AUTH_TRAP || state == AUTH_DONE)
        return true;
    return false;
}

char * auth_parser_error_report(enum auth_trap_cause error_cause) {
    switch(error_cause) {
        case AUTH_VALID:
            return "Auth-parser: no error";
        break;

        case AUTH_INVALID_VERSION:
            return "Auth-parser: invalid version provided";
        break;

        case AUTH_INVALID_USERNAME_LEN:
            return "Auth-parser: invalid username length";
        break;

        case AUTH_INVALID_PASSWORD_LEN:
            return "Auth-parser: invalid password length";
        break;

        default: return "Auth-parser: trap state"; break;
    }
}