// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include <stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "hello_parser.h"
#include "request_parser.h"
#include "auth_parser.h"
#include "args.h"
#include "buffer.h"
#include "stm.h"
#include "socksv5_nio.h"
#include "netutils.h"
#include "stm.h"
#include "logger.h"
#include "pop3_sniffer.h"
#include "user_utils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))
#define MAX_CONC_CONNECTIONS 509

static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5 *pool = 0;
extern struct socks5_args socks5_args;
extern struct socks5_stats socks5_stats;

/* maquina de estados general */
enum socks_v5state {
    HELLO_READ,
    HELLO_WRITE,
    AUTH_READ,
    AUTH_WRITE,
    REQUEST_READ,
    REQUEST_RESOLV,
    REQUEST_CONNECTING,
    REQUEST_WRITE,
    COPY,

    // estados terminales
    DONE,
    ERROR,
};

//------------------------ ST_STRUCTS--------------------------

struct hello_st {

    buffer *rb, *wb;
    struct hello_parser parser;

    uint8_t method;
};

struct auth_st {
    buffer *rb, *wb;
    auth_parser parser;
    struct username *username;
    struct password *password;
    uint8_t status;
};

struct request_st {
    /** buffer utilizado para I/O */
    buffer *rb, *wb;

    struct socks5_request request;
    struct request_parser parser;

    enum socks5_response_status status;

    struct sockaddr_storage *origin_addr;
    socklen_t *origin_addr_len;
    int *origin_domain;

    const int *client_fd;
    int *origin_fd;
};

//------------------------------------------------------------
struct copy {
    int *fd;
    fd_interest duplex;
    buffer *rb, *wb;
    struct copy *other;
};
struct connecting {
    buffer *wb;
    const int *client_fd;
    int *origin_fd;
    enum socks5_response_status *status;
};

//------------------------------------------------------------

//--------------------FUNCTION DEFINITIONS------------------
static void hello_read_init(const unsigned state, struct selector_key *key);
static unsigned hello_process(const struct hello_st *d);
static unsigned hello_read(struct selector_key *key);
static unsigned request_connect(struct selector_key *key, struct request_st *d);
static unsigned hello_write(struct selector_key *key);
static void auth_init(const unsigned state, struct selector_key *key);
static uint8_t check_auth_credentials(const struct auth_st *d);
static unsigned auth_process(struct auth_st *d);
static unsigned auth_read(struct selector_key *key);
static unsigned auth_write(struct selector_key *key);
static void request_init(const unsigned state, struct selector_key *key);
static unsigned request_read(struct selector_key *key);
static unsigned request_resolv_done(struct selector_key *key);
static void request_connecting_init(const unsigned state,
                                    struct selector_key *key);
static unsigned request_connecting(struct selector_key *key);
static unsigned request_write(struct selector_key *key);
static void copy_init(const unsigned state, struct selector_key *key);
static unsigned copy_read(struct selector_key *key);
static unsigned copy_write(struct selector_key *key);
static struct copy *fd_copy(struct selector_key *key);
static fd_interest copy_compute_interests(fd_selector s, struct copy *d);
//---------------------------------------------------------------

/* definicion de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state = HELLO_READ,
        .on_arrival = hello_read_init,
        .on_read_ready = hello_read,
    },
    {
        .state = HELLO_WRITE,
        .on_write_ready = hello_write,
    },
    {
        .state = AUTH_READ,
        .on_arrival = auth_init,
        .on_read_ready = auth_read,
    },
    {.state = AUTH_WRITE, .on_write_ready = auth_write},
    {
        .state = REQUEST_READ,
        .on_arrival = request_init,
        .on_read_ready = request_read,
    },
    {
        .state = REQUEST_RESOLV,
        .on_block_ready = request_resolv_done,
    },
    {
        .state = REQUEST_CONNECTING,
        .on_arrival = request_connecting_init,
        .on_write_ready = request_connecting,
    },
    {
        .state = REQUEST_WRITE,
        .on_write_ready = request_write,
    },
    {
        .state = COPY,
        .on_arrival = copy_init,
        .on_read_ready = copy_read,
        .on_write_ready = copy_write,
    },
    {.state = DONE},
    {.state = ERROR}

};
struct socks5 {

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    int client_fd;

    struct addrinfo *origin_resolution;
    struct addrinfo *origin_resolution_current;

    struct sockaddr_storage origin_addr;
    socklen_t origin_addr_len;
    int origin_domain;
    int origin_fd;

    /** maquinas de estados */
    struct state_machine stm;

    /** estados para el client_fd */
    union {
        struct hello_st hello;
        struct request_st request;
        struct auth_st auth;
        struct copy copy;
    } client;

    union {
        struct connecting conn;
        struct copy copy;
    } orig;

    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer read_buffer, write_buffer;

    /** Cantidad de referencias a este objeto. si es uno se debe destruir. */
    unsigned references;

    int error;

    struct pop3_sniffer_parser pop3_sniffer;

    struct log_data log_data;

    struct socks5 *next;
};

/** realmente destruye */
static void socks5_destroy_(struct socks5 *s) {
    if (s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

static void socks5_destroy(struct socks5 *s) {
    if (s == NULL) {
        // nada para hacer
    } else if (s->references == 1) {
        if (s != NULL) {
            if (pool_size < max_pool) {
                s->next = pool;
                pool = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for (s = pool; s != NULL; s = next) {
        next = s->next;

        log_print(DEBUG, "Socks5 pool destroy");
        if(s->origin_resolution != NULL) {
            free(s->origin_resolution);
        }
        close(s->origin_fd);
        close(s->client_fd);
        free(s);
    }
    pool = NULL;
}

#define ATTACHMENT(key) ((struct socks5 *)(key)->data)

static void socksv5_read(struct selector_key *key);
static void socksv5_write(struct selector_key *key);
static void socksv5_block(struct selector_key *key);
static void socksv5_close(struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read = socksv5_read,
    .handle_write = socksv5_write,
    .handle_close = socksv5_close,
    .handle_block = socksv5_block,
};

static struct socks5 *socks5_new(int client_fd) {
    struct socks5 *ret;
    char *error_message;

    if (pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if (ret == NULL) {
        error_message = "Failed to create socks";
        log_print(LOG_ERROR, error_message);
        return NULL;
    }

    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial = HELLO_READ;
    ret->stm.max_state = ERROR;
    ret->stm.states = client_statbl;
    stm_init(&ret->stm);

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;

    return ret;
}

static void socksv5_done(struct selector_key *key);

static void socksv5_read(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_write(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_block(struct selector_key *key) {
    struct state_machine *stm = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if (ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void socksv5_done(struct selector_key *key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };

    for (unsigned i = 0; i < N(fds); i++) {
        if (fds[i] != -1) {
            if (SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }

    dec_current_connections();
    log_print(INFO, "Connection closed, curr conn: %d", socks5_stats.current_connections);
}

void socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct socks5 *state = NULL;
    char *error_message;
    selector_status ss = SELECTOR_SUCCESS;
    int client;

    // Wait for a client to connect
    if(socks5_stats.current_connections < MAX_CONC_CONNECTIONS) {
        client = accept(key->fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client == -1) {
            error_message = "Socks5 Passive: accept client connection failed";
            goto fail;
        }
        if (selector_fd_set_nio(client) == -1) {
            error_message = "Socks5 Passive: set non block failed";
            goto fail;
        }


        state = socks5_new(client);

        if (state == NULL) {
            error_message = "Socks5 passive: new socks5 connection failed";
            goto fail;
        }

        memcpy(&state->client_addr, &client_addr, client_addr_len);
        state->client_addr_len = client_addr_len;
        state->log_data.client_addr = client_addr;

        ss = selector_register(key->s, client, &socks5_handler, OP_READ, state);
        if (SELECTOR_SUCCESS != ss) {
            error_message = "Socks5 Passive: selector error register";
            goto fail;
        }

        inc_current_connections();
    }
    return;

fail:
    if (client != -1) {
        close(client);
    }
    log_print(LOG_ERROR, error_message);
    socks5_destroy(state);
}

static void on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected = p->data;
    if (socks5_args.authentication == 1) {
        if (method == METHOD_AUTH_REQ)
            *selected = method;
    } else {
        if ((method == METHOD_NO_AUTH_REQ))
            *selected = METHOD_NO_AUTH_REQ;
    }
}

/** inicializa las variables de los estados HELLO_â€¦ */
static void hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.data = &d->method;
    *((uint8_t *)d->parser.data) = METHOD_NO_ACCEPTABLE_METHODS;
    hello_parser_init(&d->parser, on_hello_method);
}

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned ret = HELLO_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(d->rb, n);
        add_bytes_transferred(n);
        if (hello_parser_consume(d->rb, &d->parser, &error)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = hello_process(d);
            } else {
                ret = ERROR;
            }
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

/** procesamiento del mensaje `hello' */
static unsigned hello_process(const struct hello_st *d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;

    if (-1 == hello_parser_marshall(d->wb, m)) {
        ret = ERROR;
    }
    if (METHOD_NO_ACCEPTABLE_METHODS == m) {
        ret = ERROR;
    }
    return ret;
}

static unsigned hello_write(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    unsigned ret = HELLO_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(d->wb, n);
        add_bytes_transferred(n);

        if (!buffer_can_read(d->wb)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ)) {
                if (d->method == METHOD_AUTH_REQ) {
                    ret = AUTH_READ;
                } else {
                    ret = REQUEST_READ;
                }
            } else {
                ret = ERROR;
            }
        }
    }

    return ret;
}

// ////////////////  AUTH  ////////////////
static void auth_init(const unsigned state, struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    auth_parser_init(&d->parser);
    d->username = &d->parser.username;
    d->password = &d->parser.password;
}

static uint8_t check_auth_credentials(const struct auth_st *d) {
    if (check_credentials(d->username->username, d->password->password) != 0)
        return AUTH_SUCCESS;
    return AUTH_FAIL;
}

static unsigned auth_process(struct auth_st *d) {
    unsigned ret = AUTH_WRITE;
    uint8_t status = check_auth_credentials(d);
    if (auth_marshall(d->wb, status, d->parser.version) == -1) {
        ret = ERROR;
    }
    d->status = status;
    return ret;
}

static unsigned auth_read(struct selector_key *key) {
    unsigned ret = AUTH_READ;
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    bool error = false;
    uint8_t *ptr;
    buffer *buff = d->rb;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(buff, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(buff, n);
        add_bytes_transferred(n);
        if (auth_parser_consume(buff, &d->parser, &error)) {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
                ret = auth_process(d);
                strcpy(ATTACHMENT(key)->log_data.username,
                       d->parser.username.username);
            } else {
                error = true;
                ret = ERROR;
            }
        }

    } else {
        error = true;
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static unsigned auth_write(struct selector_key *key) {
    struct auth_st *d = &ATTACHMENT(key)->client.auth;
    unsigned ret = AUTH_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;
    buffer *buff = d->wb;
    ptr = buffer_read_ptr(buff, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (d->status != AUTH_SUCCESS) {
        ret = ERROR;
    } else if (n > 0) {
        buffer_read_adv(buff, n);
        add_bytes_transferred(n);

        if (!buffer_can_read(buff)) {
            if (selector_set_interest_key(key, OP_READ) == SELECTOR_SUCCESS) {
                ret = REQUEST_READ;
            } else {
                ret = ERROR;
            }
        }
    }
    return ret;
}

// ////////////////////////////////////////
////////////////  REQUEST  ////////////////

static void *request_resolv_blocking(void *data) {
    struct selector_key *key = (struct selector_key *)data;
    struct socks5 *s = ATTACHMENT(key);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;

    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = 0,
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char buff[7];
    snprintf(buff, sizeof(buff), "%d",
             ntohs(s->client.request.request.dest_port));

    if(getaddrinfo(s->client.request.request.dest_addr.fqdn, buff, &hints,
                &s->origin_resolution) < 0) {
        s->origin_resolution = NULL;
    }
    s->origin_resolution_current = s->origin_resolution;

    selector_notify_block(key->s, key->fd);

    free(data);

    return 0;
}

static unsigned request_resolv_done(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(key);
    if (s->origin_resolution == NULL) {
        log_print(INFO, "Resolution failed");
        d->status = SOCKS5_STATUS_HOST_UNREACHABLE;
        s->log_data.response_status = d->status;
        if (-1 != request_marshall(d->wb, d->status, d->request.dest_addr_type,
                                   d->request.dest_addr,
                                   d->request.dest_port)) {
            if(SELECTOR_SUCCESS != selector_set_interest(key->s, *d->client_fd, OP_WRITE)) {
                return ERROR;
            }
            return REQUEST_WRITE;
        } else {
            return ERROR;
        }

    } else {
        log_print(INFO, "Resolution success");
        s->origin_domain = s->origin_resolution_current->ai_family;
        s->origin_addr_len = s->origin_resolution_current->ai_addrlen;
        memcpy(&s->origin_addr, s->origin_resolution_current->ai_addr,
               s->origin_resolution_current->ai_addrlen);
    }

    return request_connect(key, d);
}

static void request_init(const unsigned state, struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.request = &d->request;
    d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
    request_parser_init(&d->parser);
    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;

    d->origin_addr = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain = &ATTACHMENT(key)->origin_domain;
}

static unsigned request_process(struct selector_key *key,
                                struct request_st *d) {
    unsigned ret;
    pthread_t tid;
    struct selector_key *k;
    switch (d->request.cmd) {
        case SOCKS5_REQ_CMD_CONNECT:
            // esto mejoraría enormemente de haber usado
            // sockaddr_storage en el request
            ATTACHMENT(key)->log_data.dest_addr_atyp = d->request.dest_addr_type;
            switch (d->request.dest_addr_type) {
            case SOCKS5_REQ_ADDRTYPE_IPV4: 
                ATTACHMENT(key)->origin_domain = AF_INET;
                d->request.dest_addr.ipv4.sin_port = d->request.dest_port;
                ATTACHMENT(key)->origin_addr_len =
                    sizeof(d->request.dest_addr.ipv4);
                memcpy(&ATTACHMENT(key)->origin_addr, &d->request.dest_addr,
                    sizeof(d->request.dest_addr.ipv4));
                memcpy(&ATTACHMENT(key)->log_data.dest_addr, &d->request.dest_addr,
                    sizeof(d->request.dest_addr.ipv4));
                ATTACHMENT(key)->log_data.dest_port = d->request.dest_port;
                ret = request_connect(key, d);
                break;
            
            case SOCKS5_REQ_ADDRTYPE_IPV6: 
                ATTACHMENT(key)->origin_domain = AF_INET6;
                d->request.dest_addr.ipv6.sin6_port = d->request.dest_port;
                ATTACHMENT(key)->origin_addr_len =
                    sizeof(d->request.dest_addr.ipv6);
                memcpy(&ATTACHMENT(key)->origin_addr, &d->request.dest_addr,
                    sizeof(d->request.dest_addr.ipv6));
                memcpy(&ATTACHMENT(key)->log_data.dest_addr, &d->request.dest_addr,
                    sizeof(d->request.dest_addr.ipv6));
                ATTACHMENT(key)->log_data.dest_port = d->request.dest_port;
                ret = request_connect(key, d);
                break;
            
            case SOCKS5_REQ_ADDRTYPE_DOMAIN: 
                k = malloc(sizeof(*key));
                if (k == NULL) {
                    ret = REQUEST_WRITE;
                    d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
                    if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE))
                        ret = ERROR;
                } else {
                    memcpy(k, key, sizeof(*k));
                    if (-1 == pthread_create(&tid, 0, request_resolv_blocking, k)) {
                        ret = REQUEST_WRITE;
                        d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
                        if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) 
                            ret = ERROR;
                        ATTACHMENT(key)->log_data.response_status = d->status;
                    } else {
                        ret = REQUEST_RESOLV;
                        if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP)) 
                            ret = ERROR;
                        memcpy(ATTACHMENT(key)->log_data.dest_addr.fqdn,
                            d->request.dest_addr.fqdn,
                            sizeof(d->request.dest_addr.fqdn));
                        ATTACHMENT(key)->log_data.dest_port = d->request.dest_port;
                    }
                }
                break;
            default: 
                ret = REQUEST_WRITE;
                d->status = SOCKS5_STATUS_ADDRTYPE_NOT_SUPPORTED;
                if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_WRITE)) {
                    ret = ERROR;
                    d->status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
                }
            }
            break;
        case SOCKS5_REQ_CMD_BIND:
        case SOCKS5_REQ_CMD_ASSOCIATE:
        default:
            d->status = SOCKS5_STATUS_CMD_NOT_SUPPORTED;
            ret = REQUEST_WRITE;
            break;
    }

    return ret;
}

static unsigned request_read(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    buffer *b = d->rb;
    unsigned ret = REQUEST_READ;
    bool error = false;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_write_ptr(b, &count);
    n = recv(key->fd, ptr, count, 0);
    if (n > 0) {
        buffer_write_adv(b, n);
        add_bytes_transferred(n);

        if (request_parser_consume(b, &d->parser, &error)) {
            ret = request_process(key, d);
        }
    } else {
        ret = ERROR;
    }

    return error ? ERROR : ret;
}

static void request_connecting_init(const unsigned state,
                                    struct selector_key *key) {
    struct connecting *d = &ATTACHMENT(key)->orig.conn;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status = &ATTACHMENT(key)->client.request.status;
    d->wb = &ATTACHMENT(key)->write_buffer;
}

/** intenta establecer una conexión con el origin server */
static unsigned request_connect(struct selector_key *key,
                                struct request_st *d) {
    bool error = false;
    enum socks5_response_status status = d->status;
    int *fd = d->origin_fd;


    // Creo el socket
    *fd = socket(ATTACHMENT(key)->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1) {
        error = true;
        goto finally;
    }
    // Lo seteo como no bloqueante
    if (selector_fd_set_nio(*fd) == -1) {
        goto finally;
    }

    if (-1 == connect(*fd,
                      (const struct sockaddr *)&ATTACHMENT(key)->origin_addr,
                      ATTACHMENT(key)->origin_addr_len)) {
        if (errno == EINPROGRESS) {
            log_print(INFO, "Connect in progress");
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if (SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }
            st = selector_register(key->s, *fd, &socks5_handler, OP_WRITE,
                                   key->data);
            if (SELECTOR_SUCCESS != st) {
                error = true;
                goto finally;
            }
            ATTACHMENT(key)->references += 1;
        } else {
            log_print(INFO, "Connect failed");
            status = errno_to_socks(errno);
            error = true;
            goto finally;
        }
    } else {
        abort();
    }

finally:
    if (error) {
        if (*fd != -1) {
            close(*fd);
            *fd = -1;
        }
    }

    d->status = status;
    ATTACHMENT(key)->log_data.response_status = d->status;

    // El siguiente estado es el Connecting
    return REQUEST_CONNECTING;
}

// la conexion ha sido establecida (o fallo)
static unsigned request_connecting(struct selector_key *key) {
    int error;
    socklen_t len = sizeof(error);
    unsigned ret = REQUEST_CONNECTING;
    struct socks5 *s = ATTACHMENT(key);
    struct request_st *d = &ATTACHMENT(key)->client.request;
    if (getsockopt(*s->orig.conn.origin_fd, SOL_SOCKET, SO_ERROR, &error,
                   &len) == 0) {
        if(SELECTOR_SUCCESS != selector_set_interest(key->s, *s->orig.conn.client_fd, OP_WRITE)) {
            s->client.request.status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
            ATTACHMENT(key)->log_data.response_status = s->client.request.status;
            ret = ERROR;    
        } else if (error == 0) {
            log_print(INFO, "Connection success");
            s->client.request.status = SOCKS5_STATUS_SUCCEED;
        } else {
            if (s->origin_resolution_current != NULL) {
                s->origin_resolution_current =
                    s->origin_resolution_current->ai_next;
                if (s->origin_resolution_current != NULL) {
                    log_print(INFO, "Connection retry");
                    s->origin_domain = s->origin_resolution_current->ai_family;
                    s->origin_addr_len =
                        s->origin_resolution_current->ai_addrlen;
                    memcpy(&s->origin_addr,
                           s->origin_resolution_current->ai_addr,
                           s->origin_resolution_current->ai_addrlen);

                    return request_connect(key, d);
                }
            }
            log_print(LOG_ERROR, "Connection failed");
            s->client.request.status = errno_to_socks(error);
            if( SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP)) {
                ret = ERROR;
                s->client.request.status = SOCKS5_STATUS_GENERAL_SERVER_FAILURE;
            }
            ATTACHMENT(key)->log_data.response_status =
                s->client.request.status;
        }
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;

        if (-1 != request_marshall(s->orig.conn.wb, *s->orig.conn.status,
                                   s->client.request.request.dest_addr_type,
                                   s->client.request.request.dest_addr,
                                   s->client.request.request.dest_port)) {
            ret = REQUEST_WRITE;
            if(SELECTOR_SUCCESS != selector_set_interest(key->s, *s->orig.conn.origin_fd, OP_READ)) {
                ret = ERROR;
            }
        } else {
            ret = ERROR;
        }
        ATTACHMENT(key)->log_data.response_status = s->client.request.status;
    }

    return ret;
}

static unsigned request_write(struct selector_key *key) {
    struct request_st *d = &ATTACHMENT(key)->client.request;

    buffer *b = d->wb;
    unsigned ret = REQUEST_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;
    ptr = buffer_read_ptr(b, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);

    if (n == -1) {
        ret = ERROR;
    } else {
        buffer_read_adv(b, n);
        add_bytes_transferred(n);

        if (!buffer_can_read(b)) {
            ret = COPY;
            if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_READ)) {
                ret = ERROR;
            }
        }
        sign_in_print((&ATTACHMENT(key)->log_data));
    }

    return ret;
}

////////////////////////////////////////
////////////// COPY ///////////////////

static struct copy *fd_copy(struct selector_key *key) {
    struct copy *d = &ATTACHMENT(key)->client.copy;
    return *d->fd == key->fd ? d : d->other;
}

static void pop3_sniffer(struct selector_key *key, uint8_t *ptr, ssize_t size) {
    struct pop3_sniffer_parser *p = &ATTACHMENT(key)->pop3_sniffer;
    if (!p->is_initiated) {
        pop3_sniffer_parser_init(p);
    }
    if (!pop3_sniffer_parser_is_done(p)) {
        size_t count;
        uint8_t *pop3_ptr = buffer_write_ptr(&p->buffer, &count);

        if ((unsigned)size <= count) {
            memcpy(pop3_ptr, ptr, size);
            buffer_write_adv(&p->buffer, size);
        } else {
            memcpy(pop3_ptr, ptr, count);
            buffer_write_adv(&p->buffer, count);
        }
        pop3_sniffer_parser_consume(p, &ATTACHMENT(key)->log_data);
    }
}

static void copy_init(const unsigned state, struct selector_key *key) {
    struct copy *d = &ATTACHMENT(key)->client.copy;

    d->fd = &ATTACHMENT(key)->client_fd;
    d->rb = &ATTACHMENT(key)->read_buffer;
    d->wb = &ATTACHMENT(key)->write_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &ATTACHMENT(key)->orig.copy;

    d = &ATTACHMENT(key)->orig.copy;
    d->fd = &ATTACHMENT(key)->origin_fd;
    d->rb = &ATTACHMENT(key)->write_buffer;
    d->wb = &ATTACHMENT(key)->read_buffer;
    d->duplex = OP_READ | OP_WRITE;
    d->other = &ATTACHMENT(key)->client.copy;
}

static unsigned copy_read(struct selector_key *key) {
    struct copy *d = fd_copy(key);
    size_t size;
    ssize_t n;
    buffer *b = d->rb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_write_ptr(b, &size);
    n = recv(key->fd, ptr, size, 0);
    if (n <= 0) {
        shutdown(*d->fd, SHUT_RD);
        d->duplex &= ~OP_READ;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_WR);
            d->other->duplex &= ~OP_WRITE;
        }
    } else {
        if (socks5_args.spoofing) {
            pop3_sniffer(key, ptr, n);
        }
        buffer_write_adv(b, n);
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);
    if (d->duplex == OP_NOOP) {
        ret = DONE;
    }

    return ret;
}

static unsigned copy_write(struct selector_key *key) {
    struct copy *d = fd_copy(key);
    size_t size;
    ssize_t n;
    buffer *b = d->wb;
    unsigned ret = COPY;

    uint8_t *ptr = buffer_read_ptr(b, &size);
    n = send(key->fd, ptr, size, MSG_NOSIGNAL);
    if (n == -1) {
        shutdown(*d->fd, SHUT_WR);
        d->duplex &= ~OP_WRITE;
        if (*d->other->fd != -1) {
            shutdown(*d->other->fd, SHUT_RD);
            d->other->duplex &= ~OP_READ;
        }
    } else {
        add_bytes_transferred(n);
        if (socks5_args.spoofing) {
            pop3_sniffer(key, ptr, n);
        }
        buffer_read_adv(b, n);
    }

    copy_compute_interests(key->s, d);
    copy_compute_interests(key->s, d->other);

    if (d->duplex == OP_NOOP) {
        ret = DONE;
    }

    return ret;
}

static fd_interest copy_compute_interests(fd_selector s, struct copy *d) {
    fd_interest ret = OP_NOOP;

    if (*d->fd != -1) {
        if (((d->duplex & OP_READ) && buffer_can_write(d->rb))) {
            ret |= OP_READ;
        }
        if ((d->duplex & OP_WRITE) && buffer_can_read(d->wb)) {
            ret |= OP_WRITE;
        }
        if (SELECTOR_SUCCESS != selector_set_interest(s, *d->fd, ret)) {
            abort();
        }
    }

    return ret;
}
