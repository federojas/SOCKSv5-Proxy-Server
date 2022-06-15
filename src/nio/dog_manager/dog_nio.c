#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "args.h"
#include "logger.h"
#include "dog_nio.h"
#include "buffer.h"
#include "stm.h"
#include "auth_parser.h"

#define ATTACHMENT(key) ((struct manager*)key->data)
#define N(x) (sizeof(x)/sizeof((x)[0]))

struct auth_st {
    buffer               *rb, *wb;
    auth_parser          parser;
    struct username*         username;
    struct password*     password;
    uint8_t              status;
};

struct manager {

    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    struct state_machine          stm;

    union {
        struct auth_st            auth;
        struct cmd_St             cmd;
    } client;

    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer read_buffer, write_buffer;
};

const struct fd_handler manager_handler = {
    .handle_read = manager_read,
    .handle_write = manager_write,
    .handle_close = manager_close,
};


static const struct state_definition client_manager_states[] = {
    {
        .state = DOG_AUTH_READ,
        .on_arrival = dog_auth_init,
        .on_read_ready = dog_auth_read,
    },
    {
        .state = DOG_AUTH_WRITE,
        .on_write_ready = dog_auth_write,
    },
    {
        .state = DOG_CMD_READ,
        .on_arrival = dog_cmd_init,
        .on_read_ready = dog_cmd_read,
    },
    {
        .state = DOG_CMD_WRITE,
        .on_write_ready = dog_cmd_write,
    },
    {
        .state=DONE,
    },
    {
        .state=ERROR,
    }
};



void manager_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct manager * state = NULL;
    char * error_message;
    selector_status ss = SELECTOR_SUCCESS;

    // Wait for a client to connect
    const int client = accept(key->fd, (struct sockaddr *) &client_addr,
                                                           &client_addr_len);

    if(client == -1) {
        error_message = "Manager Passive: accept client connection failed";
        goto fail;
    }

    if (selector_fd_set_nio(client) == -1) {
        error_message = "Manager Passive: set non block failed";
        goto fail;
    }
 
    state = manager_new(client);
     if(state == NULL) {
        error_message = "Manager Passive: new manager connection failed";
        goto fail;
    }

    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;

    ss = selector_register(key->s, client, &manager_handler, OP_READ, state);
    if (SELECTOR_SUCCESS != ss) {
        error_message = "Manager Passive: selector error register";
        goto fail;
    }

    return;

fail:
    if (client != -1) {
        close(client);
    }
    log_print(LOG_ERROR, error_message);

    free(state);
}

static void manager_close(struct selector_key *key){
    if(key->data != NULL) {
        free(key->data);
        key->data = NULL;
    }
}

static struct manager *manager_new(int client_fd) {
    struct manager *ret;

    ret = malloc(sizeof(*ret));
    if(ret == NULL) {
        log_print(LOG_ERROR, "Failed to create manager");
        return NULL;
    }
    
    memset(ret, 0x00, sizeof(*ret));

    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial=AUTH_READ;
    ret->stm.max_state=ERROR;
    ret->stm.states=client_manager_states;
    stm_init(&(ret->stm));   

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    return ret;
}
   
// ////////////////  AUTH  ////////////////

static void dog_auth_init(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    auth_parser_init(&d->parser,AUTH_MNG);
    d->username = &d->parser.username;
    d->password = &d->parser.password;
}
         

static unsigned dog_auth_read(struct selector_key *key){
    unsigned ret = AUTH_READ;
    struct auth_st * d = &ATTACHMENT(key)->client.auth;
    bool error = false;
    uint8_t *ptr;
    buffer * buff = d->rb;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(buff,&count);
    n = recv(key->fd,ptr,count,0);
    if (n > 0){
        buffer_write_adv(buff,n);
        if(auth_consume(buff,&d->parser,&error)){
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_process(d);
            }
            else {
                ret = ERROR;
            }
        }

    }
   else{
        error = true;
        ret = ERROR;
    }

        

    return error ? ERROR : ret;
}

static unsigned dog_auth_write(struct selector_key *key){
    struct auth_st * d = &ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;
    buffer *buff = d->wb;
    ptr = buffer_read_ptr(buff,&count);
    n = send(key->fd,ptr,count,MSG_NOSIGNAL);

    if(d->status != AUTH_SUCCESS){
        ret = ERROR;
    }
    else if (n > 0){
        buffer_read_adv(buff,n);
        if(!buffer_can_read(buff)){
            if(selector_set_interest_key(key,OP_READ) == SELECTOR_SUCCESS){
                ret = CMD_READ;
            }
            else{
                ret = ERROR;
            }
        }
    }
    return ret;
}


    
