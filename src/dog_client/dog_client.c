#include "args.h"
#include "dog.h"
#include "logger.h"
#include "netutils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define USER_INPUT_SIZE 100
#define TIMEOUT_SEC 5
#define MAX_ATTEMPS 3
#define MAX_COMMANDS 12
#define COLOR_OFF "\033[0m"
#define BGREEN "\033[1;32m"
typedef bool (*req_builder)(struct dog_request *, char *);
void help();
static bool get_list_builder(struct dog_request *, char *);
static bool get_historic_conn_builder(struct dog_request *, char *);
static bool get_conc_conn_builder(struct dog_request *, char *);
static bool get_bytes_transf_builder(struct dog_request *, char *);
static bool get_sniffing_builder(struct dog_request *, char *);
static bool get_auth_builder(struct dog_request *, char *);
static bool get_user_page_size_builder(struct dog_request *, char *);
static bool alter_add_user_builder(struct dog_request *, char *);
static bool alter_del_user_builder(struct dog_request *, char *);
static bool alter_toggle_sniff_builder(struct dog_request *, char *);
static bool alter_toggle_auth_builder(struct dog_request *, char *);
static bool alter_user_page_size_builder(struct dog_request *, char *);
static void header_builder(struct dog_request *dog_request, dog_type type,
                           unsigned cmd);
void response_handler(struct dog_request dog_request,
                      struct dog_response dog_response, char *message);
void print_help_table();
void print_command(char *command);
void print_usage(char *usage);
void print_description(char *description);

/* comandos para implementacion tipo shell */
typedef struct dog_client_command {
    char *name;
    char *usage;
    char *description;
    char *on_success_message;
    req_builder builder;
    size_t nparams;
} dog_client_command;

// Si se agrega un comando, cambiar el define de MAX_COMMANDS
dog_client_command dog_client_commands[] = {
    {.name = "list",
     .usage = "list <page_number>",
     .builder = get_list_builder,
     .nparams = 1,
     .description = "Returns the specified page of the list of users "
                    "registered on the server",
     .on_success_message = "Users"},
    {.name = "hist",
     .usage = "hist",
     .builder = get_historic_conn_builder,
     .nparams = 0,
     .description =
         "Returns the amount of historic connections over the server",
     .on_success_message = "Amount of historic connections"},
    {.name = "conc",
     .usage = "conc",
     .builder = get_conc_conn_builder,
     .nparams = 0,
     .description =
         "Returns the amount of concurrent connections over the server",
     .on_success_message = "Amount of concurrent connections"},
    {.name = "bytes",
     .usage = "bytes",
     .builder = get_bytes_transf_builder,
     .nparams = 0,
     .description = "Returns the amount of bytes transfered over the server",
     .on_success_message = "Amount of bytes transfered"},
    {.name = "checksniff",
     .usage = "checksniff",
     .builder = get_sniffing_builder,
     .nparams = 0,
     .description =
         "Returns the status of the password disector over the server",
     .on_success_message = "POP3 credential sniffer status"},
    {.name = "checkauth",
     .usage = "checkauth",
     .builder = get_auth_builder,
     .nparams = 0,
     .description = "Returns the status of authentication over the server",
     .on_success_message = "Authentication status"},
    {.name = "getpage",
     .usage = "getpage",
     .builder = get_user_page_size_builder,
     .nparams = 0,
     .description = "Returns the amount of users per page (max 200)",
     .on_success_message = "Users per page"},
    {.name = "add",
     .usage = "add user:pass",
     .builder = alter_add_user_builder,
     .nparams = 1,
     .description = "Command to add a user",
     .on_success_message = "User added successfully"},
    {.name = "del",
     .usage = "del user",
     .builder = alter_del_user_builder,
     .nparams = 1,
     .description = "Command to delete a user",
     .on_success_message = "User deleted successfully"},
    {.name = "sniff",
     .usage = "sniff on/off",
     .builder = alter_toggle_sniff_builder,
     .nparams = 1,
     .description = "Command to toggle POP3 credential sniffer over the server",
     .on_success_message = "POP3 credential sniffer toggled!"},
    {.name = "auth",
     .usage = "auth on/off",
     .builder = alter_toggle_auth_builder,
     .nparams = 1,
     .description = "Command to toggle authentication over the server",
     .on_success_message = "Authentication toggled!"},
    {.name = "setpage",
     .usage = "setpage <page_size>",
     .builder = alter_user_page_size_builder,
     .nparams = 1,
     .description = "Command to set page size (between 1 and 200)",
     .on_success_message = "Page size set successfully"},
};

static bool done = false;
static struct dog_request dog_req;
static struct dog_response dog_res;
uint16_t id_counter;
uint32_t token;

int main(int argc, const char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: ./dog <dog_server_addr> <dog_server_port>\n");
        exit(EXIT_FAILURE);
    }

    char *token_env = getenv(DOG_TOKEN);
    if (token_env == NULL || strlen(token_env) != TOKEN_SIZE) {
        fprintf(stderr, "Dog client: ERROR, erroneous or unexistent DOG_TOKEN "
                        "env variable.\n");
        fprintf(stderr,
                "The token name must be DOG_TOKEN and its value 4 bytes\n");
        exit(EXIT_FAILURE);
    }
    token = strtoul(token_env, NULL, 10);

    int sockfd, valid_param, port, ip_type = ADDR_IPV4;
    struct sockaddr_in serv_addr;
    struct sockaddr_in6 serv_addr6;
    char buffer_in[BUFFER_SIZE], buffer_out[BUFFER_SIZE],
        user_input[USER_INPUT_SIZE], *command, *param;
    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&serv_addr6, 0, sizeof(serv_addr6));

    if ((port = htons(atoi(argv[2]))) <= 0) {
        fprintf(stderr, "Dog client: ERROR. Invalid port\n");
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr.s_addr) > 0) {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = port;
        ip_type = ADDR_IPV4;
    } else if (inet_pton(AF_INET6, argv[1], &serv_addr6.sin6_addr) > 0) {
        serv_addr6.sin6_family = AF_INET6;
        serv_addr6.sin6_port = port;
        ip_type = ADDR_IPV6;
    }

    if ((sockfd = socket(ip_type == ADDR_IPV4 ? AF_INET : AF_INET6, SOCK_DGRAM,
                         0)) < 0) {
        fprintf(stderr, "Dog client: ERROR. Unable to create socket\n");
        exit(EXIT_FAILURE);
    }

    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        fprintf(stderr,
                "Dog client: ERROR. Failed manager client setsockopt\n");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    for (; !done;) {
        command = param = NULL;
        printf("%s", BGREEN);
        printf("dog client >> ");
        printf("%s", COLOR_OFF);

        memset(user_input, 0, USER_INPUT_SIZE);
        fgets(user_input, USER_INPUT_SIZE, stdin);

        if (user_input[0] == 0) {
            printf("No command specified.\n");
            continue;
        }

        user_input[strcspn(user_input, "\r\n")] = 0;
        command = user_input;
        param = strchr(user_input, ' ');
        if (param != NULL) {
            *param++ = 0;
        }

        if (strcmp(command, "help") == 0) {
            help();
            continue;
        }

        int i;
        for (i = 0; i < MAX_COMMANDS; i++) {
            if (strcmp(command, dog_client_commands[i].name) == 0) {
                if ((dog_client_commands[i].nparams != 0 && param == NULL) ||
                    (dog_client_commands[i].nparams == 0 && param != NULL)) {
                    valid_param = false;
                } else {
                    valid_param =
                        dog_client_commands[i].builder(&dog_req, param);
                }
                break;
            }
        }
        if (i == MAX_COMMANDS) {
            printf("Invalid command.\n");
            continue;
        }
        if (valid_param == false) {
            printf("Invalid parameter\n");
            printf("Command: %s\t usage: %s\t description: %s\n",
                   dog_client_commands[i].name, dog_client_commands[i].usage,
                   dog_client_commands[i].description);
            continue;
        }

        int req_size;
        ssize_t resp_size;
        socklen_t len;

        memset(buffer_in, 0, BUFFER_SIZE);
        memset(buffer_out, 0, BUFFER_SIZE);

        if (dog_request_to_packet(buffer_out, &dog_req, &req_size) < 0) {
            fprintf(stderr, "Error building dog packet");
        }

        if (ip_type == ADDR_IPV4) {
            sendto(sockfd, buffer_out, req_size, MSG_CONFIRM,
                   (const struct sockaddr *)&serv_addr, sizeof(serv_addr));

            resp_size =
                recvfrom(sockfd, (char *)buffer_in, BUFFER_SIZE, MSG_WAITALL,
                         (struct sockaddr *)&serv_addr, &len);
        } else {
            sendto(sockfd, buffer_out, req_size, MSG_CONFIRM,
                   (const struct sockaddr *)&serv_addr6, sizeof(serv_addr6));

            resp_size =
                recvfrom(sockfd, (char *)buffer_in, BUFFER_SIZE, MSG_WAITALL,
                         (struct sockaddr *)&serv_addr6, &len);
        }

        // Timeout
        if (resp_size < 0) {
            printf("Destination unreachable.\n");
            continue;
        }

        if (raw_packet_to_dog_response(buffer_in, &dog_res) < 0) {
            fprintf(stderr, "Error converting raw packet to response");
            continue;
        }

        response_handler(dog_req, dog_res,
                         dog_client_commands[i].on_success_message);
    }
}

void help() { print_help_table(); }

void print_help_table() {
    printf("+------------+---------------------+-------------------------------"
           "-------------------------------------------+\n");
    printf("|  Command   |        Usage        |                               "
           "Description                                |\n");
    printf("+------------+---------------------+-------------------------------"
           "-------------------------------------------+\n");
    for (int i = 0; i < MAX_COMMANDS; i++) {
        printf("| ");
        print_command(dog_client_commands[i].name);
        printf(" | ");
        print_usage(dog_client_commands[i].usage);
        printf(" | ");
        print_description(dog_client_commands[i].description);
        printf(" |\n");
    }
    printf("+------------+---------------------+-------------------------------"
           "-------------------------------------------+\n");
}

void print_command(char *command) {
    printf("%s", BGREEN);
    printf("%s", command);
    printf("%s", COLOR_OFF);

    for (int i = strlen(command); i < 10; i++) {
        printf(" ");
    }
}

void print_usage(char *usage) {
    printf("%s", usage);
    for (int i = strlen(usage); i < 19; i++) {
        printf(" ");
    }
}

void print_description(char *description) {
    printf("%s", description);
    for (int i = strlen(description); i < 72; i++) {
        printf(" ");
    }
}

static bool get_list_builder(struct dog_request *dog_request, char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_LIST);
    int size = atoi(input);
    if (size <= 0)
        return false;
    dog_request->current_dog_data.dog_uint8 = size;
    return true;
}

static bool get_historic_conn_builder(struct dog_request *dog_request,
                                      char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_HIST_CONN);
    return true;
}

static bool get_conc_conn_builder(struct dog_request *dog_request,
                                  char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_CONC_CONN);
    return true;
}

static bool get_bytes_transf_builder(struct dog_request *dog_request,
                                     char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_BYTES_TRANSF);
    return true;
}
static bool get_sniffing_builder(struct dog_request *dog_request, char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_IS_SNIFFING_ENABLED);
    return true;
}

static bool get_auth_builder(struct dog_request *dog_request, char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_IS_AUTH_ENABLED);
    return true;
}

static bool get_user_page_size_builder(struct dog_request *dog_request,
                                       char *input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_USER_PAGE_SIZE);
    return true;
}

static bool alter_add_user_builder(struct dog_request *dog_request,
                                   char *input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    if (*input == USER_PASS_DELIMETER)
        return false;
    char *temp = strchr(input, USER_PASS_DELIMETER);
    if (temp == NULL || strlen(temp) > MAX_CRED_SIZE || *(temp++) == '\0' ||
        strlen(temp) > MAX_CRED_SIZE)
        return false;
    strcpy(dog_request->current_dog_data.string, input);
    return true;
}

static bool alter_del_user_builder(struct dog_request *dog_request,
                                   char *input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_DEL_USER);
    if (input == NULL || strlen(input) > MAX_CRED_SIZE)
        return false;
    strcpy(dog_request->current_dog_data.string, input);
    return true;
}

static bool alter_toggle_sniff_builder(struct dog_request *dog_request,
                                       char *input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_TOGGLE_SNIFFING);
    if (strcmp(input, "on") == 0 || strcmp(input, "off") == 0) {
        // TODO: usamos memcpy ya que atoi devuelve int en lugar de uint8? por
        // overflow?
        dog_request->current_dog_data.dog_uint8 =
            strcmp(input, "on") == 0 ? 1 : 0;
        return true;
    }

    return false;
}

static bool alter_toggle_auth_builder(struct dog_request *dog_request,
                                      char *input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_TOGGLE_AUTH);
    if (strcmp(input, "on") == 0 || strcmp(input, "off") == 0) {
        // TODO: usamos memcpy ya que atoi devuelve int en lugar de uint8? por
        // overflow?
        dog_request->current_dog_data.dog_uint8 =
            strcmp(input, "on") == 0 ? 1 : 0;
        return true;
    }
    return false;
}

static bool alter_user_page_size_builder(struct dog_request *dog_request,
                                         char *input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_USER_PAGE_SIZE);
    int arg = atoi(input);
    if (arg >= MIN_PAGE_SIZE && arg <= MAX_PAGE_SIZE) {
        dog_request->current_dog_data.dog_uint8 = arg;
        return true;
    }
    return false;
}

static void header_builder(struct dog_request *dog_request, dog_type type,
                           unsigned cmd) {
    dog_request->dog_version = DOG_V1;
    dog_request->dog_type = type;
    dog_request->current_dog_cmd = cmd;
    dog_request->req_id = id_counter++;
    dog_request->token = token;
}

void response_handler(struct dog_request dog_request,
                      struct dog_response dog_response, char *message) {
    if (dog_request.req_id != dog_response.req_id) {
        printf("Error: fallo el req id.\n");
        return;
    }

    if (dog_response.dog_status_code != SC_OK) {
        printf("Error: %s.\n", error_report(dog_response.dog_status_code));
        return;
    }

    switch (cmd_to_resp_data_type(dog_response.dog_type,
                                  dog_response.current_dog_cmd)) {
    case UINT_8_DATA:
        printf("%s: %d", message, dog_response.current_dog_data.dog_uint8);
        break;
    case UINT_16_DATA:
        printf("%s: %d", message, dog_response.current_dog_data.dog_uint16);
        break;
    case UINT_32_DATA:
        printf("%s: %u", message, dog_response.current_dog_data.dog_uint32);
        break;
    case STRING_DATA:
        printf("%s:\n%s", message, dog_response.current_dog_data.string);
        break;
    case EMPTY_DATA:
        printf("done\n");
        break;
    default:
        printf("%s", message);
        break;
    }
    printf("\n");
}