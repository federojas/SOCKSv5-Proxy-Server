#include <string.h>
#include "dog_parser.h"

uint8_t get_cmds[] = {CMD_LIST_USERS, CMD_HISTORIC_CONNECTIONS, CMD_CONCURRENT_CONNECTIONS, CMD_BYTES_QTY, CMD_SPOOF_STATUS, CMD_AUTH_STATUS};
uint8_t alter_cmds[][2] = {{CMD_ADD_USR, 5}, {CMD_DEL_USR, 2}, {CMD_TOGGLE_SPOOF, 1}, {CMD_TOGGLE_AUTH, 1}};

void dog_parser_init(dog_parser *p) {
    p->remaining_bytes = 0;
    p->read_bytes = 0;
    p->current_state = DOG_REQUEST_TYPE;
}

static enum dog_state cmd_type(dog_parser *p, uint8_t byte) {
    if(byte <= 0x02){
        p->request_type = byte;
        if(byte == 0x02){
            p->reply_status = STATUS_SUCCEDED;
            return DOG_REQUEST_SUCCESS;
        }
    }
    else {
        p->trap_cause = DOG_REQUEST_TRAP_UNSUPPORTED_TYPE;
        p->reply_status = STATUS_UNSUPPORTED_TYPE;
        return DOG_REQUEST_TRAP;
    }
    return DOG_REQUEST_CMD;
}

static enum dog_state cmd(dog_parser *p, uint8_t byte) {
    if(p->request_type == 0x00 && byte < GET_COMMANDS_TOTAL) {
        p->cmd.get_cmd = get_cmds[byte];
        p->reply_status = STATUS_SUCCEDED;
        return DOG_REQUEST_SUCCESS;
    }
    else if(p->request_type == 0x01 && byte < ALTER_COMMANDS_TOTAL) {
        p->cmd.alter_cmd = alter_cmds[byte][0];
        p->args_qty = alter_cmds[byte][1];
        return DOG_REQUEST_CMD_QARGS;
    }

    p->trap_cause = DOG_REQUEST_TRAP_UNSUPPORTED_CMD;
    p->reply_status = STATUS_UNSUPPORTED_CMD;
    return DOG_REQUEST_TRAP;
}

static enum dog_state args_qty(dog_parser *p, uint8_t byte) {
    if(byte > 0 && p->args_qty == byte) {
        p->remaining_bytes = byte;
        p->read_bytes = 0;
        p->args_ptr = 0;
    } else {
        p->reply_status = STATUS_INVALID_ARG;
        p->trap_cause = DOG_REQUEST_TRAP_INVALID_ARG_QTY;
        return DOG_REQUEST_TRAP;
    }
    return DOG_REQUEST_CMD_ARGS;
}

static enum dog_state args(dog_parser *p, uint8_t byte) {
    uint8_t current = p->args_qty - p->remaining_bytes;
    if(p->args_ptr - p->read_bytes == 0) {
        p->read_bytes = 0;
        p->args_ptr = byte;
        if(p->args_ptr == 0){
            p->reply_status = STATUS_INVALID_ARG;
            p->trap_cause = DOG_REQUEST_TRAP_INVALID_ARG_QTY;
            return DOG_REQUEST_TRAP;
        }   
        return DOG_REQUEST_CMD_ARGS;
    }
    if(p->read_bytes < MAX_ARGS_SIZE) {
        p->args[current][p->read_bytes++] = byte;
        if(p->args_ptr - p->read_bytes == 0) {
            p->args[current][p->read_bytes] = 0;
            p->remaining_bytes--;
            if(p->remaining_bytes == 0){
                p->reply_status = STATUS_SUCCEDED;
                return DOG_REQUEST_SUCCESS;
            }
        }
    } else {
        p->reply_status = STATUS_INVALID_ARG;
        p->trap_cause = DOG_REQUEST_TRAP_INVALID_ARG_SIZE;
        return DOG_REQUEST_TRAP;
    }
    return DOG_REQUEST_CMD_ARGS;
}


enum dog_state dog_parser_feed(dog_parser *p, const uint8_t byte) {
    switch (p->current_state) {

        case DOG_REQUEST_TYPE:
            p->current_state = cmd_type(p, byte);
        break;

        case DOG_REQUEST_CMD:
            p->current_state = cmd(p, byte);
        break;

        case DOG_REQUEST_CMD_QARGS:
            p->current_state = args_qty(p, byte);
        break;

        case DOG_REQUEST_CMD_ARGS:
            p->current_state = args(p, byte);
        break;

        case DOG_REQUEST_SUCCESS:
        case DOG_REQUEST_TRAP:
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
        if(state == DOG_REQUEST_TRAP)
            *errored = true;
        else
            *errored = false;
    }
    if(state == DOG_REQUEST_TRAP || state == DOG_REQUEST_SUCCESS)
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

    if(nwrite > 0) {
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

        case DOG_REQUEST_TRAP_UNSUPPORTED_TYPE:
            return "Dog-parser: unsupported request type provided";
        break;

        case DOG_REQUEST_TRAP_UNSUPPORTED_CMD:
            return "Dog-parser: unsupported command provided";
        break;

        case DOG_REQUEST_TRAP_INVALID_ARG_QTY:
            return "Dog-parser: invalid argument quantity provided";
        break;

        case DOG_REQUEST_TRAP_INVALID_ARG_SIZE:
            return "Dog-parser: invalid argument provided, max argument size is 255";
        break;
        default: return "Dog-parser: trap state"; break;
    }
}