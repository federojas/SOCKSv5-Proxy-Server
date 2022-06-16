/**
 * dog_manager.c  - administrador de servidor SOCKSv5
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include "dog_manager.h"
#include "dog.h"
#include "args.h"
#include "buffer.h"
#include "logger.h"

#define BUFFER_SIZE 4096

#define N(x) (sizeof(x)/sizeof((x)[0]))
typedef void (*resp_handler_fun) (dog_response *, dog_request);
extern struct socks5_stats socks5_stats;
extern struct socks5_args socks5_args;

void get_cmd_list_handler(dog_response * dog_response, dog_request dog_request);
void get_cmd_hist_conn_handler(dog_response * dog_response, dog_request dog_request);
void get_cmd_conc_conn_handler(dog_response * dog_response, dog_request dog_request);
void get_cmd_bytes_transf_handler(dog_response * dog_response, dog_request dog_request);
void get_cmd_is_sniffing_handler(dog_response * dog_response, dog_request dog_request);
void get_cmd_is_auth_handler(dog_response * dog_response, dog_request dog_request);
void alter_cmd_add_user_handler(dog_response * dog_response, dog_request dog_request);
void alter_cmd_del_user_handler(dog_response * dog_response, dog_request dog_request);
void alter_cmd_toggle_sniffing_handler(dog_response * dog_response, dog_request dog_request);
void alter_cmd_toggle_auth_handler(dog_response * dog_response, dog_request dog_request);

resp_handler_fun get_handlers[] = {
    get_cmd_list_handler,
    get_cmd_hist_conn_handler,
    get_cmd_conc_conn_handler,
    get_cmd_bytes_transf_handler,
    get_cmd_is_sniffing_handler,
    get_cmd_is_auth_handler,
};

resp_handler_fun alter_handlers[] = {
    alter_cmd_add_user_handler,
    alter_cmd_del_user_handler,
    alter_cmd_toggle_sniffing_handler,
    alter_cmd_toggle_auth_handler
};


struct dog_manager {
    struct dog_request dog_request;
    struct dog_response dog_response;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    size_t response_len;
    
    char buffer_read[BUFFER_SIZE], buffer_write[BUFFER_SIZE];
};

static bool check_admin_token(struct dog_request dog_request);


void manager_passive_accept(struct selector_key *key) {

    struct dog_manager dog_manager;
    dog_manager.client_addr_len = sizeof(dog_manager.client_addr);
    dog_manager.response_len = 0;

    memset(dog_manager.buffer_read, 0, BUFFER_SIZE);
    memset(dog_manager.buffer_write, 0, BUFFER_SIZE);

    ssize_t n = recvfrom(key->fd, dog_manager.buffer_read, BUFFER_SIZE, 0, 
                        (struct sockaddr *)&dog_manager.client_addr, &dog_manager.client_addr_len);

    if (n <= 0) {
        log_print(LOG_ERROR, "Dog manager: recvfrom failed: %s ", strerror(errno));
    }

    if (raw_packet_to_dog_request(dog_manager.buffer_read, &dog_manager.dog_request) < 0) {
        log_print(LOG_ERROR,"Dog manager: converting raw packet to request failed");
    }

    setResponseHeader(dog_manager.dog_request, &dog_manager.dog_response);

    if(dog_manager.dog_response.dog_status_code == SC_OK) {
        if(dog_manager.dog_request.dog_type == TYPE_GET)
            get_handlers[dog_manager.dog_request.current_dog_cmd];
        else
            alter_handlers[dog_manager.dog_request.current_dog_cmd];
    }
   
    if (dog_response_to_packet(dog_manager.buffer_write, &dog_manager.dog_response, 
                               &dog_manager.response_len) < 0) {
        log_print(LOG_ERROR, "Dog manager: converting response to buffer failed");
    }

    if(sendto(key->fd, dog_manager.buffer_write, dog_manager.response_len, 0, 
              (const struct sockaddr *)&dog_manager.client_addr, dog_manager.client_addr_len) < 0 ) {
        log_print(LOG_ERROR, "Dog manager: sendto client not available");
    }

}

static bool check_admin_token(struct dog_request dog_request) {
    if(dog_request.token != "1234")
        return false;
    return true;
}

static bool check_version(struct dog_request dog_request) {
    if(dog_request.dog_version != DOG_V1)
        return false;
    return true;
}

static bool check_type(struct dog_request dog_request) {
    if(dog_request.dog_type != TYPE_GET && dog_request.dog_type != TYPE_ALTER)
        return false;
    return true;
}

static bool check_cmd(struct dog_request dog_request) {
    if(dog_request.dog_type == TYPE_GET && dog_request.current_dog_cmd > GET_CMD_QTY) {
        return false;
    } else if(dog_request.dog_type == TYPE_ALTER && dog_request.current_dog_cmd > ALTER_CMD_QTY) {
        return false;
    }
    return true;
}

static bool check_alter_uint8(struct dog_request dog_request) {
    if(dog_request.current_dog_data.dog_uint8 != false && dog_request.current_dog_data.dog_uint8 != true)
        return false;
    return true;
}

static bool check_alter_add_user(char * string) {
    char * temp = strchr(string, ':');
    if(temp == NULL) 
        return false;
    if(*temp++ == NULL)
        return false;
    return true;
}

static bool check_alter_string(struct dog_request dog_request) {
    bool ret = true;
    switch(dog_request.current_dog_cmd) {
        case ALTER_CMD_ADD_USER:
            if(check_alter_add_user(dog_request.current_dog_data.string))
                ret = false;
        case ALTER_CMD_DEL_USER:
            if(dog_request.current_dog_data.string == "\0" )
                ret = false;
    }
    return ret;
}


static bool check_arguments(struct dog_request dog_request) {
    bool ret = false;
    switch(cmd_to_req_data_type(dog_request.dog_type, dog_request.current_dog_cmd)) {
        case UINT_8_DATA:
            ret = check_alter_uint8(dog_request);
        break ;
        case STRING_DATA:
            ret = check_alter_string(dog_request);
        break ;
        default:
        break ;
    }
    return ret;
}

static void setResponseHeader(struct dog_request dog_request, struct dog_response * dog_response) {
    if(check_version(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_VERSION;
    } else if(check_admin_token(dog_request) == false) {
        dog_response->dog_status_code = SC_BAD_CREDENTIALS;
    } else if(check_type(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_TYPE;
    } else if(check_cmd(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_COMMAND;
    } else if(check_arguments(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_ARGUMENT;
    }
    dog_response->dog_status_code = SC_OK;
    dog_response->dog_version = DOG_V1;
    dog_response->req_id = dog_request.req_id;
    dog_response->dog_type = dog_request.dog_type;
    dog_response->current_dog_cmd = dog_request.current_dog_cmd;
}


// TODO: terminar algunas funciones

void get_cmd_list_handler(dog_response * dog_response, dog_request dog_request) {
    
}

void get_cmd_hist_conn_handler(dog_response * dog_response, dog_request dog_request) {
    dog_response->current_dog_data.dog_uint32 = socks5_stats.historic_connections;
}

void get_cmd_conc_conn_handler(dog_response * dog_response, dog_request dog_request) {
    dog_response->current_dog_data.dog_uint16 = socks5_stats.current_connections;
}

void get_cmd_bytes_transf_handler(dog_response * dog_response, dog_request dog_request) {
    dog_response->current_dog_data.dog_uint32 = socks5_stats.bytes_transfered;
}

void get_cmd_is_sniffing_handler(dog_response * dog_response, dog_request dog_request) {
    dog_response->current_dog_data.dog_uint8 = socks5_args.spoofing;
}

void get_cmd_is_auth_handler(dog_response * dog_response, dog_request dog_request) {
    dog_response->current_dog_data.dog_uint8 = socks5_args.authentication;
}

// TODO: Hacer un mejor manejo de usuarios

void alter_cmd_add_user_handler(dog_response * dog_response, dog_request dog_request) {
    if(socks5_args.nusers < MAX_USERS) {
        // if(new_user tipo bool)
        // } else {
        //     dog_response->dog_status_code = SC_INVALID_USER_IS_REGISTERED;
        // }
    } else {
        dog_response->dog_status_code = SC_SERVER_IS_FULL;
    }   
}

void alter_cmd_del_user_handler(dog_response * dog_response, dog_request dog_request) {
    //CHEQUEAR QUE EXISTA
}

void alter_cmd_toggle_sniffing_handler(dog_response * dog_response, dog_request dog_request) {
    socks5_args.spoofing = dog_request.current_dog_data.dog_uint8;
}

void alter_cmd_toggle_auth_handler(dog_response * dog_response, dog_request dog_request) {
    socks5_args.authentication = dog_request.current_dog_data.dog_uint8;
}