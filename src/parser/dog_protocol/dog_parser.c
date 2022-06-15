#include <string.h>
#include "dog_parser.h"

void dog_parser_init(dog_parser *p) {
    p->remaining_bytes = 0;
    p->read_bytes = 0;
    p->current_state = REQUEST_TYPE;
}

enum dog_state dog_parser_feed(dog_parser *p, const uint8_t byte) {
    switch (p->current_state) {

        case REQUEST_TYPE:
            p->current_state = REQUEST_SUCCESS;
        break;

        case REQUEST_CMD:
            p->current_state = REQUEST_SUCCESS;
        break;

        case REQUEST_CMD_QARGS:
            p->current_state = REQUEST_SUCCESS;
        break;

        case REQUEST_CMD_ARGS:
            p->current_state = REQUEST_SUCCESS;
        break;

        case REQUEST_SUCCESS:
        case REQUEST_TRAP:
            // Nothing to do
        break;
        
        default:
            log_print(DEBUG,"Unknown state on DOG parser");
            abort();
        break;
    }

    return p->current_state;
}

bool dog_parser_is_done(enum dog_state state, bool *errored) {
    if(errored != NULL) {
        if(state == REQUEST_TRAP)
            *errored = true;
        else
            *errored = false;
    }
    if(state == REQUEST_TRAP || state == REQUEST_SUCCESS)
        return true;
    return false;
}

enum dog_state dog_parser_consume(buffer *buffer, struct dog_parser *p, bool *errored) {
    uint8_t byte;

    while (buffer_can_read(buffer) && !dog_parser_is_done(p->current_state, errored)) {
        byte = buffer_read(buffer);
        p->current_state = dog_parser_feed(p, byte);
    }

    return p->current_state;
}

int dog_marshall(buffer* buffer, const uint8_t status, uint8_t *response, size_t nwrite) {
    size_t count;
    uint8_t * buff = buffer_write_ptr(buffer, &count);

    if(count < nwrite + 1){
        return -1;
    }

    buff[0] = status;

    buffer_write_adv(buffer,1);

    if(nwrite > 0){
        memcpy(buff+1, response, nwrite);
        buffer_write_adv(buffer, nwrite);
        free(response);
    }

    return nwrite;
}

char * dog_parser_error_report(enum dog_trap_cause trap_cause) {
    switch(trap_cause) {
        case DOG_VALID:
            return "Dog-parser: no error";
        break;

        case REQUEST_TRAP_UNSUPPORTED_TYPE:
            return "Dog-parser: unsupported request type provided";
        break;

        case REQUEST_TRAP_UNSUPPORTED_CMD:
            return "Dog-parser: unsupported command provided";
        break;

        default: return "Dog-parser: trap state"; break;
    }
}