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
#define DEFAULT_PAGE 1

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

struct dog_request dog_request;
struct dog_response dog_response;
uint16_t id_counter;
uint32_t token;

// TODO: 
int main(int argc, const char *argv[])
{
    return 0;
}

void help();

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

// TODO: terminar los alters
static bool alter_del_user_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);

    return true;
}

static bool alter_toggle_sniff_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    return true;
}

static bool alter_toggle_auth_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    return true;
}

static bool alter_user_page_size_builder(struct dog_request * dog_request, char * input) {
    header_builder(dog_request, TYPE_ALTER, ALTER_CMD_ADD_USER);
    return true;
}

static void header_builder(struct dog_request * dog_request, dog_type type, unsigned cmd) {
    dog_request->dog_version = DOG_V1;
    dog_request->dog_type = type;
    dog_request->current_dog_cmd = cmd;
    dog_request->req_id = id_counter++;
    dog_request->token = token;
}

void response_handler(struct dog_request dog_request, struct dog_response dog_response, char *message);