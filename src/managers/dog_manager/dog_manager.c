/**
 * dog_manager.c  - administrador de servidor SOCKSv5
 */
#include "dog_manager.h"
#include "args.h"
#include "buffer.h"
#include "dog.h"
#include "logger.h"
#include "user_utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define BUFFER_SIZE 4096
#define DEFAULT_PAGE_SIZE 200
#define N(x) (sizeof(x) / sizeof((x)[0]))
typedef void (*resp_handler_fun)(dog_response *, dog_request);
extern struct socks5_stats socks5_stats;
extern struct socks5_args socks5_args;

static void setResponseHeader(struct dog_request dog_request,
                              struct dog_response *dog_response);
static bool check_admin_token(struct dog_request dog_request);
static bool check_version(struct dog_request dog_request);
static bool check_type(struct dog_request dog_request);
static bool check_cmd(struct dog_request dog_request);
static bool check_alter_uint8(struct dog_request dog_request);
static bool check_alter_add_user(char *string);
static bool check_alter_string(struct dog_request dog_request);
static bool check_arguments(struct dog_request dog_request);

static void get_cmd_list_handler(dog_response *dog_response,
                                 dog_request dog_request);
static void get_cmd_hist_conn_handler(dog_response *dog_response,
                                      dog_request dog_request);
static void get_cmd_conc_conn_handler(dog_response *dog_response,
                                      dog_request dog_request);
static void get_cmd_bytes_transf_handler(dog_response *dog_response,
                                         dog_request dog_request);
static void get_cmd_is_sniffing_handler(dog_response *dog_response,
                                        dog_request dog_request);
static void get_cmd_is_auth_handler(dog_response *dog_response,
                                    dog_request dog_request);
static void get_cmd_user_page_size(dog_response *dog_response,
                                   dog_request dog_request);
static void alter_cmd_add_user_handler(dog_response *dog_response,
                                       dog_request dog_request);
static void alter_cmd_del_user_handler(dog_response *dog_response,
                                       dog_request dog_request);
static void alter_cmd_toggle_sniffing_handler(dog_response *dog_response,
                                              dog_request dog_request);
static void alter_cmd_toggle_auth_handler(dog_response *dog_response,
                                          dog_request dog_request);
static void alter_cmd_user_page_size(dog_response *dog_response,
                                     dog_request dog_request);

resp_handler_fun get_handlers[] = {
    get_cmd_list_handler,        get_cmd_hist_conn_handler,
    get_cmd_conc_conn_handler,   get_cmd_bytes_transf_handler,
    get_cmd_is_sniffing_handler, get_cmd_is_auth_handler,
    get_cmd_user_page_size,
};

resp_handler_fun alter_handlers[] = {
    alter_cmd_add_user_handler,        alter_cmd_del_user_handler,
    alter_cmd_toggle_sniffing_handler, alter_cmd_toggle_auth_handler,
    alter_cmd_user_page_size,
};

struct dog_manager {
    struct dog_request dog_request;
    struct dog_response dog_response;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    int response_len;
    uint8_t page_size;

    char buffer_read[BUFFER_SIZE], buffer_write[BUFFER_SIZE];
};

struct dog_manager dog_manager;

void manager_passive_accept(struct selector_key *key) {

    dog_manager.client_addr_len = sizeof(dog_manager.client_addr);
    dog_manager.response_len = 0;
    dog_manager.page_size =
        dog_manager.page_size == 0 ? DEFAULT_PAGE_SIZE : dog_manager.page_size;
    memset(dog_manager.buffer_read, 0, BUFFER_SIZE);
    memset(dog_manager.buffer_write, 0, BUFFER_SIZE);
    memset(&dog_manager.dog_request, 0, sizeof(dog_request));
    memset(&dog_manager.dog_response, 0, sizeof(dog_response));
    memset(&dog_manager.client_addr, 0, sizeof(struct sockaddr_storage));

    ssize_t n = recvfrom(key->fd, dog_manager.buffer_read, BUFFER_SIZE, 0,
                         (struct sockaddr *)&dog_manager.client_addr,
                         &dog_manager.client_addr_len);

    if (n <= 0) {
        log_print(LOG_ERROR, "Dog manager: recvfrom failed: %s ",
                  strerror(errno));
    }

    if (raw_packet_to_dog_request(dog_manager.buffer_read,
                                  &dog_manager.dog_request) < 0) {
        log_print(LOG_ERROR,
                  "Dog manager: converting raw packet to request failed");
    }

    setResponseHeader(dog_manager.dog_request, &dog_manager.dog_response);

    if (dog_manager.dog_response.dog_status_code == SC_OK) {
        if (dog_manager.dog_request.dog_type == TYPE_GET)
            get_handlers[dog_manager.dog_request.current_dog_cmd](
                &dog_manager.dog_response, dog_manager.dog_request);
        else
            alter_handlers[dog_manager.dog_request.current_dog_cmd](
                &dog_manager.dog_response, dog_manager.dog_request);
    }

    if (dog_response_to_packet(dog_manager.buffer_write,
                               &dog_manager.dog_response,
                               &dog_manager.response_len) < 0) {
        log_print(LOG_ERROR,
                  "Dog manager: converting response to buffer failed");
    }

    if (sendto(key->fd, dog_manager.buffer_write, dog_manager.response_len, 0,
               (const struct sockaddr *)&dog_manager.client_addr,
               dog_manager.client_addr_len) < 0) {
        log_print(LOG_ERROR, "Dog manager: sendto client not available");
    }
}

static bool check_admin_token(struct dog_request dog_request) {
    if (dog_request.token != socks5_args.manager_token)
        return false;
    return true;
}

static bool check_version(struct dog_request dog_request) {
    if (dog_request.dog_version != DOG_V1)
        return false;
    return true;
}

static bool check_type(struct dog_request dog_request) {
    if (dog_request.dog_type != TYPE_GET && dog_request.dog_type != TYPE_ALTER)
        return false;
    return true;
}

static bool check_cmd(struct dog_request dog_request) {
    if (dog_request.dog_type == TYPE_GET &&
        dog_request.current_dog_cmd > GET_CMD_QTY) {
        return false;
    } else if (dog_request.dog_type == TYPE_ALTER &&
               dog_request.current_dog_cmd > ALTER_CMD_QTY) {
        return false;
    }
    return true;
}

static bool check_alter_uint8(struct dog_request dog_request) {
    uint8_t arg = dog_request.current_dog_data.dog_uint8;
    switch (dog_request.current_dog_cmd) {
    case ALTER_CMD_TOGGLE_SNIFFING:
    case ALTER_CMD_TOGGLE_AUTH:
        if (arg != false && arg != true)
            return false;
        break;
    case ALTER_CMD_USER_PAGE_SIZE:
        if (arg > MAX_PAGE_SIZE || arg < MIN_PAGE_SIZE)
            return false;
        break;
    default:
        break;
    }

    return true;
}

static bool check_alter_add_user(char *string) {
    if (*string == USER_PASS_DELIMETER)
        return false;
    char *temp = strchr(string, USER_PASS_DELIMETER);
    if (temp == NULL || strlen(temp) > MAX_CRED_SIZE || *(temp++) == '\0' ||
        strlen(temp) > MAX_CRED_SIZE)
        return false;
    return true;
}

static bool check_alter_string(struct dog_request dog_request) {
    switch (dog_request.current_dog_cmd) {
    case ALTER_CMD_ADD_USER:
        if (!check_alter_add_user(dog_request.current_dog_data.string))
            return false;
    case ALTER_CMD_DEL_USER:
        if (dog_request.current_dog_data.string[0] == 0 ||
            strlen(dog_request.current_dog_data.string) > MAX_CRED_SIZE)
            return false;
    }
    return true;
}

static bool check_arguments(struct dog_request dog_request) {
    bool ret = true;
    switch (cmd_to_req_data_type(dog_request.dog_type,
                                 dog_request.current_dog_cmd)) {
    case UINT_8_DATA:
        ret = check_alter_uint8(dog_request);
        break;
    case STRING_DATA:
        ret = check_alter_string(dog_request);
    default:
        break;
    }
    return ret;
}

static void setResponseHeader(struct dog_request dog_request,
                              struct dog_response *dog_response) {
    dog_response->dog_status_code = SC_OK;
    if (check_version(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_VERSION;
    } else if (check_admin_token(dog_request) == false) {
        dog_response->dog_status_code = SC_BAD_CREDENTIALS;
    } else if (check_type(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_TYPE;
    } else if (check_cmd(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_COMMAND;
    } else if (check_arguments(dog_request) == false) {
        dog_response->dog_status_code = SC_INVALID_ARGUMENT;
    }
    dog_response->dog_version = DOG_V1;
    dog_response->req_id = dog_request.req_id;
    dog_response->dog_type = dog_request.dog_type;
    dog_response->current_dog_cmd = dog_request.current_dog_cmd;
}

static void get_cmd_list_handler(dog_response *dog_response,
                                 dog_request dog_request) {
    int offset =
        (dog_request.current_dog_data.dog_uint8 - 1) * dog_manager.page_size;
    if (offset > socks5_args.nusers) {
        dog_response->current_dog_data.string[0] = 0;
        return;
    }
    int aux_offset = offset;
    int string_offset = 0;
    for (int i = 0; i < aux_offset; i++) {
        if (socks5_args.users[i].username[0] == '\0')
            offset++;
    }
    for (int i = offset, j = 0; i < MAX_USERS && j < dog_manager.page_size;
         i++) {
        if (socks5_args.users[i].username[0] != '\0') {
            strcpy(dog_response->current_dog_data.string + string_offset,
                   socks5_args.users[i].username);
            string_offset += strlen(socks5_args.users[i].username);
            *(dog_response->current_dog_data.string + string_offset++) = '\n';
            j++;
        }
    }
    *(dog_response->current_dog_data.string + --string_offset) = '\0';
}

static void get_cmd_hist_conn_handler(dog_response *dog_response,
                                      dog_request dog_request) {
    dog_response->current_dog_data.dog_uint32 =
        socks5_stats.historic_connections;
}

static void get_cmd_conc_conn_handler(dog_response *dog_response,
                                      dog_request dog_request) {
    dog_response->current_dog_data.dog_uint16 =
        socks5_stats.current_connections;
}

static void get_cmd_bytes_transf_handler(dog_response *dog_response,
                                         dog_request dog_request) {
    dog_response->current_dog_data.dog_uint32 = socks5_stats.bytes_transfered;
}

static void get_cmd_is_sniffing_handler(dog_response *dog_response,
                                        dog_request dog_request) {
    dog_response->current_dog_data.dog_uint8 = socks5_args.spoofing;
}

static void get_cmd_is_auth_handler(dog_response *dog_response,
                                    dog_request dog_request) {
    dog_response->current_dog_data.dog_uint8 = socks5_args.authentication;
}

static void get_cmd_user_page_size(dog_response *dog_response,
                                   dog_request dog_request) {
    dog_response->current_dog_data.dog_uint8 = dog_manager.page_size;
}

static void alter_cmd_add_user_handler(dog_response *dog_response,
                                       dog_request dog_request) {
    char *username = dog_request.current_dog_data.string;
    char *password;
    password = strchr(username, USER_PASS_DELIMETER);
    *password++ = 0;
    if (!server_is_full()) {
        if (!user_registerd(username)) {
            add_user(username, password);
            dog_response->dog_status_code = SC_OK;
        } else {
            dog_response->dog_status_code = SC_INVALID_USER_IS_REGISTERED;
        }
    } else {
        dog_response->dog_status_code = SC_SERVER_IS_FULL;
    }
}

static void alter_cmd_del_user_handler(dog_response *dog_response,
                                       dog_request dog_request) {
    char *username = dog_request.current_dog_data.string;
    if (user_registerd(username)) {
        delete_user(username);
        dog_response->dog_status_code = SC_OK;
    } else {
        dog_response->dog_status_code = SC_USER_NOT_FOUND;
    }
}

static void alter_cmd_toggle_sniffing_handler(dog_response *dog_response,
                                              dog_request dog_request) {
    socks5_args.spoofing = dog_request.current_dog_data.dog_uint8;
}

static void alter_cmd_toggle_auth_handler(dog_response *dog_response,
                                          dog_request dog_request) {
    socks5_args.authentication = dog_request.current_dog_data.dog_uint8;
}

static void alter_cmd_user_page_size(dog_response *dog_response,
                                     dog_request dog_request) {
    dog_manager.page_size = dog_request.current_dog_data.dog_uint8;
}