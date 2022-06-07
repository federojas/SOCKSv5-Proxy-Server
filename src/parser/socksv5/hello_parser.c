#include "hello_parser.h"
#include "logger.h"

void hello_parser_init(hello_parser *p, void (*on_auth_method)(hello_parser *p, uint8_t method), void *data) {
    p->current_state = VERSION;
    p->on_auth_method = on_auth_method;
    p->data = data;
    p->methods_remaining = 0;
}

enum hello_parser_state hello_parser_feed(hello_parser *p, const uint8_t byte) {

    switch(p->current_state) {

        case VERSION:
            if(byte == SOCKS5_VERSION)
                p->current_state = NMETHODS;
            else
                p->current_state = TRAP;
        break;

        case NMETHODS:
            p->methods_remaining = byte;
            p->current_state = byte > 0 ? METHODS : DONE;
        break;

        case METHODS:
           
            if(p->on_auth_method != NULL)
                p->on_auth_method(p,byte);
            p->methods_remaining--;
            if(p->methods_remaining <= 0)
                p->current_state = DONE;
        break;

        case DONE:
        case TRAP:
            // Nothing to do
        break;

        default:
            log(DEBUG,"Unknown state on hello parser");
            abort();
        break;
    }

    return p->current_state;
}

bool hello_parser_consume(buffer *b, hello_parser *p, bool *errored) {

    uint8_t byte;

    while(!hello_parser_is_done(p->current_state, errored) && buffer_can_read(b)) {
        byte = buffer_read(b);
        hello_parser_feed(p, byte); 
    }

    return hello_parser_is_done(p->current_state, errored);
}

bool hello_parser_is_done(enum hello_parser_state state, bool *errored) {

    if(errored != NULL)
        *errored = false;

    switch(state) {
        case DONE:
            return true;
        break;

        case VERSION:
        case NMETHODS:
        case METHODS:
            return false;
        break;

        case TRAP:
        default:
            if(errored != NULL)
                *errored = true;
            return true;
        break;
    }
}

char * hello_parser_error_message(enum hello_parser_state state) {
    switch(state) {
        case DONE:
        case VERSION:
        case NMETHODS:
        case METHODS:
            return "Hello-parser: no error";
        break;

        case TRAP:
        default:
            return "Hello-parser: on trap state";
        break;
    }
}