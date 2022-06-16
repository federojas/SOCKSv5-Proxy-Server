#include "dog.h"
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>


static int get_packet_size(dog_packet_type dog_packet_type, unsigned dog_type, unsigned dog_cmd, char* data);
static void read_dog_data(current_dog_data * output, dog_data_type dog_data_type, char* input);
static void dog_data_to_buffer(current_dog_data input, dog_data_type dog_data_type, char * output);

int raw_packet_to_dog_request(char * raw, dog_request* request) {

    if (raw == NULL || request == NULL){
        return -1;
    }

    /* Primer byte es la version */
    request->dog_version = *((uint8_t *) raw);
    raw += sizeof(uint8_t);

    /* Segundo byte es el type */
    request->dog_type = *((uint8_t *) raw);
    raw += sizeof(uint8_t);
    
    /* Tercer  y cuarto byte es el cmd */
    request->current_dog_cmd = ntohl(*((uint16_t *) raw));
    raw += sizeof(uint16_t);

    /* Quinto  y sexto byte es el id de la request */
    request->req_id = ntohl(*((uint16_t *) raw));
    raw += sizeof(uint16_t);

    /* Los proximos 8 son el token */
    request->token = ntohs(*((uint64_t *) raw));
    raw += sizeof(uint16_t);

    read_dog_data(&request->current_dog_data , op_to_req_data_type(request->dog_type, request->current_dog_cmd), raw);

    return 0;
}

int raw_packet_to_dog_response(char * raw, dog_response* response) {

    if (raw == NULL || response == NULL) {
        return ERROR;
    }

    /* Primer byte es la version */
    response->dog_version = *((uint8_t *) raw);
    raw += sizeof(uint8_t);

    /* Segundo byte es el status */
    response->dog_status_code = *((uint8_t *) raw);
    raw += sizeof(uint8_t);

    /* Tercer byte es el type */
    response->dog_type = *((uint8_t *) raw);
    raw += sizeof(uint8_t);
    
    /* Cuarto  y quinto byte es el cmd */
    response->current_dog_cmd = ntohl(*((uint16_t *) raw));
    raw += sizeof(uint16_t);

    /* Ultimos dos son el ID de la request */
    response->req_id = ntohl(*((uint16_t *) raw));
    raw += sizeof(uint16_t);

    if (response->dog_status_code == SC_OK)
        read_dog_data(&response->current_dog_data, op_to_resp_data_type(response->dog_type, response->current_dog_cmd), raw);

    return 0;

}

int dog_request_to_packet(char* output, dog_request * input, int* size) {

    if (output == NULL || input == NULL){
        return ERROR;
    }

    uint64_t aux;
    *size = get_packet_size(DOG_REQUEST,input->dog_type,input->current_dog_cmd,
                                        input->current_dog_data.string);
    char* buffer_p = output;

    aux = input->dog_version;
    memcpy(buffer_p,&aux,sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = input->dog_type;
    memcpy(buffer_p,&aux,sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = htonl(input->current_dog_cmd);
    memcpy(buffer_p,&aux,sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    aux = htons(input->req_id);
    memcpy(buffer_p,&aux,sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    aux = input->token;
    memcpy(buffer_p,&aux,sizeof(uint64_t));
    buffer_p += sizeof(uint64_t);

    dog_data_to_buffer(input->current_dog_data, op_to_req_data_type(input->dog_type,
                       input->current_dog_cmd), buffer_p);

    return 0;
}

int dog_response_to_packet(char* output, dog_response * input, int* size) {

    if (output == NULL || input == NULL){
        return -1;
    }

    uint64_t aux;
    *size = get_packet_size(DOG_RESPONSE,input->dog_type, input->current_dog_cmd, 
                            input->current_dog_data.string);
    char* buffer_p = output;

    aux = input->dog_version;
    memcpy(buffer_p, &aux, sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = input->dog_status_code;
    memcpy(buffer_p, &aux, sizeof(uint8_t));
    buffer_p += sizeof(uint8_t);

    aux = htonl(input->current_dog_cmd);
    memcpy(buffer_p, &aux, sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    aux = htonl(input->req_id);
    memcpy(buffer_p, &aux, sizeof(uint16_t));
    buffer_p += sizeof(uint16_t);

    if (input->dog_status_code == SC_OK)
        dog_data_to_buffer(input->current_dog_data, op_to_resp_data_type(input->dog_type, 
                           input->current_dog_cmd), buffer_p);

    return 0;
}

static void read_dog_data(current_dog_data * output, dog_data_type dog_data_type, char* input) {
    switch (dog_data_type) {
        case UINT_8_DATA:
            output->dog_uint8 = *((uint8_t *) input);
            break;
        case UINT_16_DATA:
            output->dog_uint16 = *((uint16_t *) input);
            break;
        case UINT_64_DATA:
            output->dog_uint64 = *((uint64_t *) input);
            break;
        case STRING_DATA:
            strcpy(output->string, input);
            break;
        case NO_DATA:
        default:
            output->string[0] = 0;
    }
}

static void dog_data_to_buffer(current_dog_data input, dog_data_type dog_data_type, char * output) {
    uint16_t aux;
    switch (dog_data_type) {
        case UINT_8_DATA:
            aux = input.dog_uint8;
            memcpy(output, &aux, sizeof(uint8_t));
            break;
        case UINT_16_DATA:
            aux = htons(input.dog_uint16);
            memcpy(output, &aux, sizeof(uint16_t));
            break;
        case UINT_64_DATA:
            aux = htons(input.dog_uint64);
            memcpy(output, &aux, sizeof(uint64_t));
            break;
        case STRING_DATA:
            strcpy(output, input.string);
            break;
        case NO_DATA:
        default:
            break;
    }
}

char* error_report(dog_status_code status_code) {
    switch (status_code) {
        case SC_OK:
            return "OK";
            break;
        case SC_AUTH_FAILED:
            return "Authentication failed";
            break;
        case SC_INVALID_VERSION:
            return "Invalid Dog version";
            break;
        case SC_INTERNAL_SERVER_ERROR:
            return "Internal Server Error";
            break;
        default:
            return "Unknown error";
    }
}

 // TODO: PENSARLO Y COMPLETARLO
dog_data_type op_to_req_data_type(unsigned dog_type, unsigned dog_cmd) {
    switch (dog_type) {
        case TYPE_GET:
            switch(dog_cmd) {
                case GET_CMD_LIST:
                case GET_CMD_HIST_CONN:
                case GET_CMD_CONC_CONN:
                case GET_CMD_BYTES_TRANSF:
                case GET_CMD_IS_SNIFFING_ENABLED:
                case GET_CMD_IS_AUTH_ENABLED:
                default:
                    return NO_DATA;
            }
        case TYPE_ALTER:
            switch(dog_cmd) {
                case ALTER_CMD_ADD_USER:
                case ALTER_CMD_DEL_USER:
                case ALTER_CMD_TOGGLE_SNIFFING:
                case ALTER_CMD_TOGGLE_AUTH:
                default:
                    return NO_DATA;
            }
        default:
            return NO_DATA;
    }
}

// TODO: PENSAR Y COMPLETAR
dog_data_type op_to_resp_data_type(unsigned dog_type, unsigned dog_cmd){
    switch (dog_type) {
        case TYPE_GET:
            switch(dog_cmd) {
                case GET_CMD_LIST:
                case GET_CMD_HIST_CONN:
                case GET_CMD_CONC_CONN:
                case GET_CMD_BYTES_TRANSF:
                case GET_CMD_IS_SNIFFING_ENABLED:
                case GET_CMD_IS_AUTH_ENABLED:
                default:
                    return NO_DATA;
            }
        case TYPE_ALTER:
            switch(dog_cmd) {
                case ALTER_CMD_ADD_USER:
                case ALTER_CMD_DEL_USER:
                case ALTER_CMD_TOGGLE_SNIFFING:
                case ALTER_CMD_TOGGLE_AUTH:
                default:
                    return NO_DATA;
            }
        default:
            return NO_DATA;
    }
}

static int get_packet_size(dog_packet_type dog_packet_type, unsigned dog_type, unsigned dog_cmd, char* data) {
    size_t size = 0;
    dog_data_type dog_data_type;
    if (dog_packet_type == DOG_REQUEST){
        size += DOG_REQUEST_HEADER_SIZE;
        dog_data_type = op_to_req_data_type(dog_type, dog_cmd);
    }
    else {
        size += DOG_RESPONSE_HEADER_SIZE;
        dog_data_type = op_to_resp_data_type(dog_type, dog_cmd);
    }

    switch (dog_data_type) {
        case UINT_8_DATA:
            size += sizeof(uint8_t);
            break;
        case UINT_16_DATA:
            size += sizeof(uint16_t);
            break;
        case UINT_64_DATA:
            size += sizeof(uint64_t);
            break;
        case STRING_DATA:
            size += (data != NULL) ? strlen(data) : 0;
            break;
        default:
            break;
    }

    return size;
}
