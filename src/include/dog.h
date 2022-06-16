#ifndef DOG_H
#define DOG_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

// in bytes
#define MAX_UDP_SIZE 65507
#define DOG_REQUEST_HEADER_SIZE 14
#define DOG_RESPONSE_HEADER_SIZE 6
#define DOG_REQUEST_ID_SIZE 2
#define ERROR -1
#define SUCCESS 0



typedef enum dog_packet_type {
    DOG_REQUEST,
    DOG_RESPONSE
} dog_packet_type;

typedef enum dog_type {
    TYPE_GET,
    TYPE_ALTER,
} dog_type;

#define GET_CMD_QTY 6

typedef enum dog_get_cmd {
    GET_CMD_LIST,
    GET_CMD_HIST_CONN,
    GET_CMD_CONC_CONN,
    GET_CMD_BYTES_TRANSF,
    GET_CMD_IS_SNIFFING_ENABLED,
    GET_CMD_IS_AUTH_ENABLED
} dog_get_cmd;

#define ALTER_CMD_QTY 4

typedef enum dog_alter_cmd {
    ALTER_CMD_ADD_USER,
    ALTER_CMD_DEL_USER,
    ALTER_CMD_TOGGLE_SNIFFING,
    ALTER_CMD_TOGGLE_AUTH
} dog_alter_cmd;

typedef enum dog_version {
    DOG_V1 = 1,
} dog_version;

typedef enum dog_status_code {
    SC_OK,
    SC_INVALID_VERSION,
    SC_BAD_CREDENTIALS,
    SC_INVALID_TYPE,
    SC_INVALID_COMMAND,
    SC_INVALID_ARGUMENT,
    SC_SERVER_IS_FULL,
    SC_INVALID_USER_IS_REGISTERED,
    SC_USER_NOT_FOUND,
    SC_INTERNAL_SERVER_ERROR,
} dog_status_code;

typedef enum dog_data_type {
    NO_DATA,
    UINT_8_DATA,
    UINT_16_DATA,
    UINT_64_DATA,
    STRING_DATA
} dog_data_type;

typedef union current_dog_data {
    uint8_t dog_uint8;
    uint16_t dog_uint16;
    uint64_t dog_uint64;
    char string[MAX_UDP_SIZE - DOG_REQUEST_HEADER_SIZE];
} current_dog_data;

/*          DOG REQUEST HEADER
 +------+-------+-----+-----+---------+
 | VER  | TYPE  | CMD |  ID |  TOKEN  |
 +------+-------+-----+-----+---------+
 |  1   |  1    |  2  |  2  |   8     |  
 +------+-------+-----+-----+---------+
*/

typedef struct dog_request {
    dog_version dog_version;
    dog_type dog_type;
    unsigned current_dog_cmd;
    uint16_t req_id;
    uint64_t token;
    current_dog_data current_dog_data;
} dog_request;

/*          DOG RESPONSE HEADER
 +------+--------+------+-----+-----+
 | VER  | STATUS | TYPE | CMD |  ID |
 +------+--------+------+-----+-----+
 |  1   |   1    |  1   |  2  |  2  |  
 +------+--------+------+-----+-----+
*/
typedef struct dog_response {
    dog_version dog_version;
    dog_status_code dog_status_code;
    dog_type dog_type;
    unsigned current_dog_cmd;
    uint16_t req_id;
    current_dog_data current_dog_data;
} dog_response;


dog_data_type cmd_to_req_data_type(unsigned dog_type, unsigned dog_cmd);

dog_data_type cmd_to_resp_data_type(unsigned dog_type, unsigned dog_cmd);

/* parser method */
int raw_packet_to_dog_request(char * raw, dog_request* request);

/* parser method */
int raw_packet_to_dog_response(char * raw, dog_response* response);

int dog_request_to_packet(char* output, dog_request * input, int* size);

int dog_response_to_packet(char* output, dog_response * input, int* size);

char* error_report(dog_status_code status_code);

#endif