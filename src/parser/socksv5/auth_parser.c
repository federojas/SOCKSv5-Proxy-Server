// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include "auth_parser.h"
#include "logger.h"

void auth_parser_init(auth_parser *p) {
    p->trap_cause = AUTH_VALID;
    p->current_state = AUTH_VERSION;
}

enum auth_parser_state auth_parser_feed(auth_parser *p, const uint8_t byte) {
    switch(p->current_state) {
        case AUTH_VERSION:
            if(byte == AUTH_VERSION_ID) {
                p->current_state = AUTH_USERNAME_LEN;
                p->version = byte;
            }    
            else {
                p->current_state = AUTH_TRAP;
                p->trap_cause = AUTH_INVALID_VERSION;
            }
        break;
        case AUTH_USERNAME_LEN:
            if(byte < 1) {
                p->trap_cause = AUTH_INVALID_USERNAME_LEN;
                p->current_state = AUTH_TRAP;
            } else {
                p->username.username_len = byte;
                p->credentials_pointer = 0;
                p->current_state = AUTH_USERNAME;
            }
        break; 
        case AUTH_USERNAME:
            p->username.username[p->credentials_pointer++] = (char) byte;
            if(p->credentials_pointer == p->username.username_len) {
                p->username.username[p->credentials_pointer] = 0;
                p->current_state = AUTH_PASSWORD_LEN;
            }
        break; 
        case AUTH_PASSWORD_LEN:
            if(byte < 1) {
                p->trap_cause = AUTH_INVALID_PASSWORD_LEN;
                p->current_state = AUTH_TRAP;
            } else {
                p->password.password_len = byte;
                p->credentials_pointer = 0;
                p->current_state = AUTH_PASSWORD;
            }
        break; 
        case AUTH_PASSWORD:
            p->password.password[p->credentials_pointer++] = (char) byte;
            if(p->credentials_pointer == p->password.password_len) {
                p->password.password[p->credentials_pointer] = 0;
                p->current_state = AUTH_DONE;
            }
        break;
        case AUTH_DONE:
        case AUTH_TRAP:
            // Nothing to do
        break;

        default:
            log_print(DEBUG,"Unknown state on auth parser");
            abort();
        break;
    }
    return p->current_state;
}

bool auth_parser_consume(buffer *buffer, auth_parser *p, bool *errored) {
    uint8_t byte;

    while(!auth_parser_is_done(p->current_state, errored) && buffer_can_read(buffer)) {
        byte = buffer_read(buffer);
        p->current_state = auth_parser_feed(p, byte); 
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

char * auth_parser_error_report(enum auth_trap_cause trap_cause) {
    switch(trap_cause) {
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

int auth_marshall(buffer *b, const uint8_t status, uint8_t version) {
    size_t n;
    uint8_t *buff = buffer_write_ptr(b, &n);
    if (n < 2) {
        return -1;
    }
    buff[0] = version;
    buff[1] = status;

    buffer_write_adv(b, 2);
    return 2; 
}