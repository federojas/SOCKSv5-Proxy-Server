#ifndef DOG_PROTOCOL_UTILS_H
#define DOG_PROTOCOL_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

typedef enum packet_type{
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

typedef enum t_get_cmd{
    CMD_LIST_USERS                  =0X00,
    CMD_HISTORIC_CONNECTIONS        =0X01,
    CMD_CONCURRENT_CONNECTIONS      =0X02,
    CMD_BYTES_QTY                   =0X03,
    CMD_SPOOF_STATUS                =0X04,
    CMD_AYTH_STATYS                 =0X05,
    INVALID_GET                     =0x06,
} t_get_cmd;

typedef enum t_alter_cmd{
    CMD_ADD_USR                     =0X00,
    CMD_DEL_USR                     =0X01,
    CMD_TOGGLE_SPOOF                =0X02,
    CMD_TOGGLE_AUTH                 =0X03,
} t_alter_cmd;


#endif