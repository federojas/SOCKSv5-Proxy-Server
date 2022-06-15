#ifndef DOG_PARSER_H
#define DOG_PARSER_H

#include <stdint.h>
#include "buffer.h"
#include "logger.h"

#define RAW_BUFF_DOG_SIZE 4096
#define GET_COMMANDS_TOTAL 6
#define ALTER_COMMANDS_TOTAL 4
#define MAX_ARGS 5
#define MAX_ARGS_SIZE 256

#define N(x) (sizeof(x)/sizeof((x)[0]))

typedef enum packet_type {
    DOG_REQUEST,
    DOG_RESPONSE
} packet_type;

//definimos el tipo de cliente para una request 
typedef enum request_type{
    T_GET               =0x00,
    T_ALTER             =0x01,
    T_END               =0x02,
    INVALID_TYPE        =0X03,
} request_type;

typedef enum dog_state {
    DOG_REQUEST_TYPE,
    DOG_REQUEST_CMD,
    DOG_REQUEST_CMD_QARGS,
    DOG_REQUEST_CMD_ARGS,
    DOG_REQUEST_SUCCESS,
    DOG_REQUEST_TRAP
} dog_state;

typedef enum dog_trap_cause {
    DOG_VALID,
    DOG_REQUEST_TRAP_UNSUPPORTED_TYPE,
    DOG_REQUEST_TRAP_UNSUPPORTED_CMD,
    DOG_REQUEST_TRAP_INVALID_ARG_QTY, 
    DOG_REQUEST_TRAP_INVALID_ARG_SIZE
} dog_trap_cause;

typedef enum t_get_cmd {
    CMD_LIST_USERS                  =0X00,
    CMD_HISTORIC_CONNECTIONS        =0X01,
    CMD_CONCURRENT_CONNECTIONS      =0X02,
    CMD_BYTES_QTY                   =0X03,
    CMD_SPOOF_STATUS                =0X04,
    CMD_AUTH_STATUS                 =0X05,
    INVALID_GET                     =0x06,
} t_get_cmd;

typedef enum t_alter_cmd {
    CMD_ADD_USR                     =0X00,
    CMD_DEL_USR                     =0X01,
    CMD_TOGGLE_SPOOF                =0X02,
    CMD_TOGGLE_AUTH                 =0X03,
    INVALID_ALTER                   =0x04,
} t_alter_cmd;

typedef union command {
    t_alter_cmd alter_cmd;
    t_get_cmd get_cmd;
} command;

typedef enum reply_status {
    STATUS_SUCCEDED = 0x00,
    STATUS_GENERAL_SERVER_FAILURE = 0x01,
    STATUS_UNSUPPORTED_TYPE = 0x02,
    STATUS_UNSUPPORTED_CMD = 0x03,
    STATUS_INVALID_ARG = 0x04,
} reply_status;

typedef struct dog_parser {
    command cmd;
    request_type request_type;
    dog_state current_state;
    dog_trap_cause trap_cause;
    reply_status reply_status;
    uint8_t args_qty;
    uint8_t args_ptr;
    uint8_t args[MAX_ARGS][MAX_ARGS_SIZE];
    uint16_t remaining_bytes;
    uint16_t read_bytes;
} dog_parser;

void dog_parser_init(dog_parser *p);

enum dog_state dog_parser_feed(dog_parser *p, const uint8_t byte);

bool dog_parser_is_done(enum dog_state state, bool *errored);

enum dog_state dog_parser_consume(buffer *buffer, struct dog_parser *p, bool *errored);

int dog_marshall(buffer* buffer, const uint8_t status, uint8_t *response, size_t nwrite);

char * dog_parser_error_report(enum dog_trap_cause trap_cause);

#endif