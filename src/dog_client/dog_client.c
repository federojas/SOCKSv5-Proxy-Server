#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "args.h"
#include "dog.h"
#include "netutils.h"
#include <sys/time.h>
#include <time.h>

#define BUFFER_SIZE 4096
#define USER_INPUT_SIZE 100
#define TIMEOUT_SEC 5
#define MAX_ATTEMPS 3
#define MAX_COMMANDS 12
#define TOKEN_SIZE 4
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
static void header_builder(struct dog_request * dog_request, dog_type type, unsigned cmd);
void response_handler(struct dog_request dog_request, struct dog_response dog_response, char *message);

/* comandos para implementacion tipo shell */
typedef struct dog_client_command {
    char *name;
    char *usage;
    char *description;
    req_builder builder;
    size_t nparams;
} dog_client_command;

// TODO: agregar las descripciones
// Si se agrega un comando, cambiar el define de MAX_COMMANDS
dog_client_command dog_client_commands[] = {
    {.name = "list", .usage = "list", .builder = get_list_builder, .nparams = 0, .description="TODO" },
    {.name = "hist", .usage = "hist", .builder = get_historic_conn_builder, .nparams = 0, .description="TODO" },
    {.name = "conc", .usage = "conc", .builder = get_conc_conn_builder, .nparams = 0, .description="TODO" },
    {.name = "bytes", .usage = "bytes", .builder = get_bytes_transf_builder, .nparams = 0, .description="TODO" },
    {.name = "checksniff", .usage = "checksniff", .builder = get_sniffing_builder, .nparams = 0, .description="TODO" },
    {.name = "checkauth", .usage = "checkauth", .builder = get_auth_builder, .nparams = 0, .description="TODO" },
    {.name = "getpage", .usage = "getpage", .builder = get_user_page_size_builder, .nparams = 0, .description="TODO" },
    {.name = "add", .usage = "add user:pass", .builder = get_user_page_size_builder, .nparams = 1, .description="TODO" },
    {.name = "del", .usage = "del user:pass", .builder = get_user_page_size_builder, .nparams = 1, .description="TODO" },
    {.name = "sniff", .usage = "sniff on / sniff off", .builder = get_user_page_size_builder, .nparams = 1, .description="TODO" },
    {.name = "auth", .usage = "auth on / auth off", .builder = get_user_page_size_builder, .nparams = 1, .description="TODO" },
    {.name = "setpage", .usage = "setpage n (n between 1 and 200)", .builder = get_user_page_size_builder, .nparams = 1, .description="TODO" },
};

static bool done = false;
static struct dog_request dog_req;
static struct dog_response dog_res;
uint16_t id_counter;
uint32_t token;

int main(int argc, const char *argv[])
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: dogc <dog_server_addr> <dog_server_port>");
        exit(EXIT_FAILURE);
    }

    char * token_env = getenv("DOG_TOKEN");
    if(token_env == NULL || strlen(token_env) != TOKEN_SIZE) {
        fprintf(stderr, "Dog client: ERROR. DOG_TOKEN envariable doesn't exist");
        exit(EXIT_FAILURE);
    }
    token = strtoul(token_env,NULL,10);

    int sockfd, valid_param, port, ip_type = ADDR_IPV4;
    struct sockaddr_in serv_addr;
    struct sockaddr_in6 serv_addr6;
    char buffer_in[BUFFER_SIZE], buffer_out[BUFFER_SIZE], 
    user_input[USER_INPUT_SIZE], *command, *param;
    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&serv_addr6, 0, sizeof(serv_addr6));

    // TODO: usar fprintf o log en los siguientes casos?
    if ((port = htons(atoi(argv[2]))) <= 0)
    {
        fprintf(stderr, "Dog client: ERROR. Invalid port");
        exit(EXIT_FAILURE);
    }

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr.s_addr) > 0)
    {
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = port;
        ip_type = ADDR_IPV4;
    }
    else if (inet_pton(AF_INET6, argv[1], &serv_addr6.sin6_addr) > 0)
    {
        serv_addr6.sin6_family = AF_INET6;
        serv_addr6.sin6_port = port;
        ip_type = ADDR_IPV6;
    }

    if ((sockfd = socket(ip_type == ADDR_IPV4 ? AF_INET : AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
        fprintf(stderr, "Dog client: ERROR. Unable to create socket");
        exit(EXIT_FAILURE);
    }

    struct timeval tv;
    tv.tv_sec = TIMEOUT_SEC;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        fprintf(stderr, "Dog client: ERROR. Failed manager client setsockopt");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    for(;!done;) {
        // TODO: pedir input y procesar
    }

}

void help() {
    for(int i = 0; i < MAX_COMMANDS; i++) {
        printf("Command: %s\t usage: %s\t description: %s\n", 
        dog_client_commands[i].name,
        dog_client_commands[i].usage, 
        dog_client_commands[i].description);
    }
}

/* requires pagination */
static bool get_list_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_LIST);
    return true;
}

static bool get_historic_conn_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_HIST_CONN);
    return true;
}

static bool get_conc_conn_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_CONC_CONN);
    return true;
}

static bool get_bytes_transf_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_BYTES_TRANSF);
    return true;
}
static bool get_sniffing_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_IS_SNIFFING_ENABLED);
    return true;
}

static bool get_auth_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_IS_AUTH_ENABLED);
    return true;
}

static bool get_user_page_size_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_GET, GET_CMD_USER_PAGE_SIZE);
    return true;
}

// TODO: max length
static bool alter_add_user_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    if(*input == USER_PASS_DELIMETER)
        return false;
    char * temp = strchr(input, USER_PASS_DELIMETER);
    if(temp == NULL || *(temp++) == '\0') 
        return false;    
    strcpy(dog_request->current_dog_data.string, input);
    return true;
}

// TODO: max length
static bool alter_del_user_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    if(input == NULL)
        return false;
    strcpy(dog_request->current_dog_data.string, input);
    return true;
}

static bool alter_toggle_sniff_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    int arg = atoi(input);
    if( arg == false || arg == true) {
        // TODO: usamos memcpy ya que atoi devuelve int en lugar de uint8? por overflow?
        dog_request->current_dog_data.dog_uint8 = arg;
        return true;
    }
        
    return false;
}

static bool alter_toggle_auth_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    int arg = atoi(input);
    if( arg == false || arg == true) {
        // TODO: usamos memcpy ya que atoi devuelve int en lugar de uint8? por overflow?
        dog_request->current_dog_data.dog_uint8 = arg;
        return true;
    }
        
    return false;
}

static bool alter_user_page_size_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    int arg = atoi(input);
    if(arg >= MIN_PAGE_SIZE && arg <= MAX_PAGE_SIZE) {
        // TODO: usamos memcpy ya que atoi devuelve int en lugar de uint8? por overflow?
        dog_request->current_dog_data.dog_uint8 = arg;
        return true;
    }
    return false;
}

static void header_builder(struct dog_request * dog_request, dog_type type, unsigned cmd) {
    dog_request->dog_version = DOG_V1;
    dog_request->dog_type = type;
    dog_request->current_dog_cmd = cmd;
    dog_request->req_id = id_counter++;
    dog_request->token = token;
}

// TODO: impl
void response_handler(struct dog_request dog_request, struct dog_response dog_response, char *message);