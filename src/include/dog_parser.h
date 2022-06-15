#ifndef DOG_PARSER_H
#define DOG_PARSER_H

#include <stdint.h>
#include "buffer.h"
#include "logger.h"

#define RAW_BUFF_DOG_SIZE 4096

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
    REQUEST_TYPE,
    REQUEST_CMD,
    REQUEST_CMD_QARGS,
    REQUEST_CMD_ARGS,
    REQUEST_SUCCESS,
    REQUEST_TRAP
} dog_state;

typedef enum dog_trap_cause {
    DOG_VALID,
    REQUEST_TRAP_UNSUPPORTED_TYPE,
    REQUEST_TRAP_UNSUPPORTED_CMD,
} dog_trap_cause;

typedef enum t_get_cmd {
    CMD_LIST_USERS                  =0X00,
    CMD_HISTORIC_CONNECTIONS        =0X01,
    CMD_CONCURRENT_CONNECTIONS      =0X02,
    CMD_BYTES_QTY                   =0X03,
    CMD_SPOOF_STATUS                =0X04,
    CMD_AYTH_STATYS                 =0X05,
    INVALID_GET                     =0x06,
} t_get_cmd;

typedef enum t_alter_cmd {
    CMD_ADD_USR                     =0X00,
    CMD_DEL_USR                     =0X01,
    CMD_TOGGLE_SPOOF                =0X02,
    CMD_TOGGLE_AUTH                 =0X03,
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
} reply_status;

typedef struct dog_parser {
    command cmd;
    request_type request_type;
    dog_state current_state;
    dog_trap_cause trap_cause;
    reply_status reply_status;
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