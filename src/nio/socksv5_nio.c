/**
 * socks5nio.c  - controla el flujo de un proxy SOCKSv5 (sockets no bloqueantes)
 */
#include<stdio.h>
#include <stdlib.h>  // malloc
#include <string.h>  // memset
#include <assert.h>  // assert
#include <errno.h>
#include <time.h>
#include <unistd.h>  // close
#include <pthread.h>

#include <arpa/inet.h>

#include "hello.h"
#include "request.h"
#include "buffer.h"

#include "stm.h"
#include "socks5nio.h"
#include"netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

static const unsigned max_pool = 50;
static unsigned pool_size = 0;
static struct socks5 * pool = 0;

static const struct state_definition * socks5_describe_states(void);


static struct socks5 * socks5_new(int client_fd) {
    struct soocks5 *ret;
    char * error_message;

    if(pool == NULL) {
        ret = malloc(sizeof(*ret));
    } else {
        ret = pool;
        pool = pool->next;
        ret->next = 0;
    }
    if(ret == NULL) {
        return NULL; //TODO error message?
    }
    
    memset(ret, 0x00, sizeof(*ret));

    ret->origin_fd = -1;
    ret->client_fd = client_fd;
    ret->client_addr_len = sizeof(ret->client_addr);

    ret->stm.initial=HELLO_READ;
    ret->stm.max_state=ERROR;
    ret->stm.states=socks5_describe_states();
    stm_init(&ret->stm);   

    buffer_init(&ret->read_buffer, N(ret->raw_buff_a), ret->raw_buff_a);
    buffer_init(&ret->write_buffer, N(ret->raw_buff_b), ret->raw_buff_b);

    ret->references = 1;

    return ret;
}


/** maquina de estados general */
enum socks_v5state {
    /**
     * recibe el mensaje `hello` del cliente, y lo procesa
     *
     * Intereses:
     *     - OP_READ sobre client_fd
     *
     * Transiciones:
     *   - HELLO_READ  mientras el mensaje no estÃ© completo
     *   - HELLO_WRITE cuando estÃ¡ completo
     *   - ERROR       ante cualquier error (IO/parseo)
     */
    HELLO_READ,

    /**
     * envÃ­a la respuesta del `hello' al cliente.
     *
     * Intereses:
     *     - OP_WRITE sobre client_fd
     *
     * Transiciones:
     *   - HELLO_WRITE  mientras queden bytes por enviar
     *   - REQUEST_READ cuando se enviaron todos los bytes
     *   - ERROR        ante cualquier error (IO/parseo)
     */
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

////////////////////////////////////////////////////////////////////
// DefiniciÃ³n de variables para cada estado

/** usado por HELLO_READ, HELLO_WRITE */
struct hello_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;
    struct hello_parser   parser;
    /** el mÃ©todo de autenticaciÃ³n seleccionado */
    uint8_t               method;
} ;

struct request_st {
    /** buffer utilizado para I/O */
    buffer               *rb, *wb;

    struct request          request;
    struct request_parser   parser;

    enum socks_response_status status;

    struct sockaddr_storage     *origin_addr;
    socklen_t                   *origin_addr_len;
    int                         *origin_domain;

    const int                   *client_fd;
    int                         *origin_fd;
} ;

/*
 * Si bien cada estado tiene su propio struct que le da un alcance
 * acotado, disponemos de la siguiente estructura para hacer una Ãºnica
 * alocaciÃ³n cuando recibimos la conexiÃ³n.
 *
 * Se utiliza un contador de referencias (references) para saber cuando debemos
 * liberarlo finalmente, y un pool para reusar alocaciones previas.
 */
struct socks5 {

    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len;
    int                           client_fd;

    struct addrinfo               *origin_resolution;
    struct addrinfo               *origin_resolution_current;


    struct sockaddr_storage       origin_addr;
    socklen_t                     origin_addr_len;
    int                           origin_domain;
    int                           origin_fd;

    /** maquinas de estados */
    struct state_machine          stm;

    /** estados para el client_fd */
    union {
        struct hello_st           hello;
        struct request_st         request;
        struct copy               copy;
    } client;
    /** estados para el origin_fd */
    union {
        struct connecting         conn;
        struct copy               copy;
    } orig;

    /** buffers **/
    //TODOS NUMEROS DIDACTICOS, HAY QUE LLEGAR A NUESTRO TAMAÑO DE BUFFER IDEAL Y JUSTIFICAR (CODA)
    uint8_t raw_buff_a[BUFFER_SIZE], raw_buff_b[BUFFER_SIZE];
    buffer read_buffer, write_buffer;

    /** Cantidad de referencias a este objeto. si es uno se debe destruir. */
    unsigned references;

    int error;

    struct socks5 *next;
};


/** realmente destruye */
static void
socks5_destroy_(struct socks5* s) {
    if(s->origin_resolution != NULL) {
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }
    free(s);
}

/**
 * destruye un  `struct socks5', tiene en cuenta las referencias
 * y el pool de objetos.
 */
static void
socks5_destroy(struct socks5 *s) {
    if(s == NULL) {
        // nada para hacer
    } else if(s->references == 1) {
        if(s != NULL) {
            if(pool_size < max_pool) {
                s->next = pool;
                pool    = s;
                pool_size++;
            } else {
                socks5_destroy_(s);
            }
        }
    } else {
        s->references -= 1;
    }
}

void
socksv5_pool_destroy(void) {
    struct socks5 *next, *s;
    for(s = pool; s != NULL ; s = next) {
        next = s->next;
        free(s);
    }
}

/** obtiene el struct (socks5 *) desde la llave de selecciÃ³n  */
#define ATTACHMENT(key) ( (struct socks5 *)(key)->data)

/* declaraciÃ³n forward de los handlers de selecciÃ³n de una conexiÃ³n
 * establecida entre un cliente y el proxy.
 */
static void socksv5_read   (struct selector_key *key);
static void socksv5_write  (struct selector_key *key);
static void socksv5_block  (struct selector_key *key);
static void socksv5_close  (struct selector_key *key);
static const struct fd_handler socks5_handler = {
    .handle_read   = socksv5_read,
    .handle_write  = socksv5_write,
    .handle_close  = socksv5_close,
    .handle_block  = socksv5_block,
};

// Handlers top level de la conexiÃ³n pasiva.
// son los que emiten los eventos a la maquina de estados.
static void
socksv5_done(struct selector_key* key);

static void
socksv5_read(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_read(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_write(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_write(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_block(struct selector_key *key) {
    struct state_machine *stm   = &ATTACHMENT(key)->stm;
    const enum socks_v5state st = stm_handler_block(stm, key);

    if(ERROR == st || DONE == st) {
        socksv5_done(key);
    }
}

static void
socksv5_close(struct selector_key *key) {
    socks5_destroy(ATTACHMENT(key));
}

static void
socksv5_done(struct selector_key* key) {
    const int fds[] = {
        ATTACHMENT(key)->client_fd,
        ATTACHMENT(key)->origin_fd,
    };
    for(unsigned i = 0; i < N(fds); i++) {
        if(fds[i] != -1) {
            if(SELECTOR_SUCCESS != selector_unregister_fd(key->s, fds[i])) {
                abort();
            }
            close(fds[i]);
        }
    }
}

/** Intenta aceptar la nueva conexiÃ³n entrante*/
void
socksv5_passive_accept(struct selector_key *key) {
    struct sockaddr_storage       client_addr;
    socklen_t                     client_addr_len = sizeof(client_addr);
    struct socks5                 *state           = NULL;
    char * error_message;
    selector_status ss = SELECTOR_SUCCESS;


    // Wait for a client to connect 
    // TODO: aca me puedo bloquear?
    const int client = accept(key->fd, (struct sockaddr*) &client_addr,
                                                          &client_addr_len);
    if(client == -1) {
        error_message = "Socks5 Passive: accept client connection failed";
        goto fail;
    }
    if(selector_fd_set_nio(client) == -1) {
        error_message = "Socks5 Passive: set non block failed";
        goto fail;
    }

    state = socks5_new(client);

    if(state == NULL) {
        // sin un estado, nos es imposible manejaro.
        // tal vez deberiamos apagar accept() hasta que detectemos
        // que se liberÃ³ alguna conexiÃ³n.
        error_message = "Socks5 Passive: new socks5 connection failed";
        goto fail;
    }


    memcpy(&state->client_addr, &client_addr, client_addr_len);
    state->client_addr_len = client_addr_len;


    ss = selector_register(key->s, client, &socks5_handler, OP_READ, state);
    if(SELECTOR_SUCCESS != ) {
        error_message = "Socks5 Passive: selector error register";
        goto fail;
    }

    //TODO ACA SEGURO FALTAN COSAS
    return ;

fail:
    if(client != -1) {
        close(client);
    }
    socks5_destroy(state);
}

//TODO SANDRINI TRANPSARENTE

//     // Como soy un tcp transparente, debo abrir un socket activo con el destino final
//     // y pasarle todo
//     // aca estoy hardcodeando una direccion cualquiera cuando en realidad
//     // deberia registrar una tarea bloqueante (getaddrinfo) que me 
//     // averigue la addrinfo del destino
//     int destSocketFd = socket(AF_INET, SOCK_STREAM, 0);
//     struct sockaddr_in serSockAddr = {.sin_family = AF_INET,
//         .sin_addr.s_addr = inet_addr("127.0.0.1"),
//         .sin_port = htons(DEST_PORT)};

//     //TODO: el connect es bloqueante, para solucionar esto tendria que 
//     // registrarlo como escritura
//     connect(destSocketFd, (struct sockaddr *) &serSockAddr, sizeof(serSockAddr));
//     // esta linea va?
//    // selector_register(key->s, destSocketFd, &activeSocketHandler, OP_WRITE, key->data);
// }

////////////////////////////////////////////////////////////////////////////////
// HELLO
////////////////////////////////////////////////////////////////////////////////

/** callback del parser utilizado en `read_hello' */
static void
on_hello_method(struct hello_parser *p, const uint8_t method) {
    uint8_t *selected  = p->data;

    if(SOCKS_HELLO_NOAUTHENTICATION_REQUIRED == method) {
       *selected = method;
    }
}

/** inicializa las variables de los estados HELLO_â€¦ */
static void
hello_read_init(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    d->rb                              = &(ATTACHMENT(key)->read_buffer);
    d->wb                              = &(ATTACHMENT(key)->write_buffer);
    d->parser.data                     = &d->method;
    d->parser.on_authentication_method = on_hello_method, hello_parser_init(
            &d->parser);
}

static unsigned
hello_process(const struct hello_st* d);

/** lee todos los bytes del mensaje de tipo `hello' y inicia su proceso */
static unsigned
hello_read(struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;
    unsigned  ret      = HELLO_READ;
        bool  error    = false;
     uint8_t *ptr;
      size_t  count;
     ssize_t  n;

    ptr = buffer_write_ptr(d->rb, &count);
    n = recv(key->fd, ptr, count, 0);
    if(n > 0) {
        buffer_write_adv(d->rb, n);
        const enum hello_state st = hello_consume(d->rb, &d->parser, &error);
        if(hello_is_done(st, 0)) {
            if(SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE)) {
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
static unsigned
hello_process(const struct hello_st* d) {
    unsigned ret = HELLO_WRITE;

    uint8_t m = d->method;
    const uint8_t r = (m == SOCKS_HELLO_NO_ACCEPTABLE_METHODS) ? 0xFF : 0x00;
    if (-1 == hello_marshall(d->wb, r)) {
        ret  = ERROR;
    }
    if (SOCKS_HELLO_NO_ACCEPTABLE_METHODS == m) {
        ret  = ERROR;
    }
    return ret;
}

static void hello_read_close(const unsigned state, struct selector_key *key) {
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    hello_parser_close(&d->parser);
}

static unsigned hello_write(struct selector_key *key)
{
    struct hello_st *d = &ATTACHMENT(key)->client.hello;

    unsigned ret = HELLO_WRITE;
    uint8_t *ptr;
    size_t count;
    ssize_t n;

    ptr = buffer_read_ptr(d->wb, &count);
    n = send(key->fd, ptr, count, MSG_NOSIGNAL);
    if (n == -1)
    {
        ret = ERROR;
    }
    else
    {
        buffer_read_adv(d->wb, n);
        if (!buffer_can_read(d->wb))
        {
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_READ))
            {
                if(d->method == METHOD_USERNAME_PASSWORD){
                    ret = AUTH_READ;
                }
                else{
                    ret = REQUEST_READ;
                }
            }
            else
            {
                ret = ERROR;
            }
        }
    }

    return ret;
}

/** definiciÃ³n de handlers para cada estado */
static const struct state_definition client_statbl[] = {
    {
        .state            = HELLO_READ,
        .on_arrival       = hello_read_init,
        .on_departure     = hello_read_close,
        .on_read_ready    = hello_read,
    },

///////////////////////////////////////////////////////////////////////////////


////////////////  AUTH  ////////////////

static void auth_init(struct selector_key *key)
{
    struct auth_st *d = &ATTACHMENT(key)->client.auth;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    auth_parser_init(&d->parser,AUTH_SOCKS);
    d->usr = &d->parser.usr;
    d->pass = &d->parser.pass;
}

static uint8_t check_credentials(const struct auth_st *d){
    if(registed((char*)d->usr->uname,(char*)d->pass->passwd) != 0) return AUTH_SUCCESS;
    return AUTH_FAIL;
}

static unsigned auth_process(struct auth_st *d){
    unsigned ret = AUTH_WRITE;
    uint8_t status = check_credentials(d);
    if(auth_marshal(d->wb,status,d->parser.version) == -1){
        ret = ERROR;
    }
    d->status = status;
    return ret;
}
static unsigned auth_read(struct selector_key *key){
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
        int st = auth_consume(buff,&d->parser,&error);
        if(auth_is_done(st,0)){
            if (SELECTOR_SUCCESS == selector_set_interest_key(key, OP_WRITE))
            {
                ret = auth_process(d);
                memcpy(&ATTACHMENT(key)->socks_info.user_info,&d->parser.usr,sizeof(d->parser.usr));
                
            }
            else{
                error = true;
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

static unsigned auth_write(struct selector_key *key){
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
                ret = REQUEST_READ;
            }
            else{
                ret = ERROR;
            }
        }
    }
    return ret;
}

////////////////////////////////////////


////////////////  REQUEST  ////////////////

static void * request_resolv_blocking(void * data) {
    struct selector_key *key = (struct selector_key *) data;
    struct socks5 *s = ATTACHMENT(key);

    pthread_detach(pthread_self());
    s->origin_resolution = 0;

    struct  addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_PASSIVE,
        .ai_protocol = 0,
        .ai_canonname = NULL,
        .ai_addr = NULL,
        .ai_next = NULL,
    };

    char buff[7]; //TODO 7??? HAY QUE DECIDIR EL TAMAÑO ACA?
    snprintf(buff, sizeof(buff), "%d", ntohs(s->client.request.request.dest_port));

    //TODO MANEJO ERRORES DE GETADDRINFO
    getaddrinfo(s->client.request.request.dest_addr.fqdn, buff, &hints, &s->origin_resolution);

    selector_notify_block(key->s, key->fd);

    free(data);

    return 0;
}

static unsigned request_resolv_done(struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;
    struct socks5 *s = ATTACHMENT(KEY);

    if(s->origin_resolution == 0) {
        d->status = status_general_SOCKS_server_failure;
    } else {
        s->origin_domain = s->origin_resolution->ai_family;
        s->origin_addr_len = s->origin_resolution->ai_addrlen;
        memcpy(&s->origin_addr, 
                s->origin_resolution->ai_addr,
                s->origin_resolution->ai_addrlen);
        freeaddrinfo(s->origin_resolution);
        s->origin_resolution = 0;
    }

    return request_connect(key, d);
}

static void request_init(const unsigned state, struct selector_key *key) {
    struct request_st * d = &ATTACHMENT(key)->client.request;

    d->rb = &(ATTACHMENT(key)->read_buffer);
    d->wb = &(ATTACHMENT(key)->write_buffer);
    d->parser.request = &d->request;
    d->status = status_general_SOCKS_server_failure;
    request_parser_init(&d->parser);
    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;

    d->origin_addr = &ATTACHMENT(key)->origin_addr;
    d->origin_addr_len = &ATTACHMENT(key)->origin_addr_len;
    d->origin_domain = &ATTACHMENT(key)->origin_domain;
}

////////////////////////////////////////


////////////////  REQUEST CONNECTING ////////////////



static void request_connecting_init(const unsigned state, struct selector_key *key) {
    struct connecting *d = &ATTACHMENT(key)->orig.conn;

    d->client_fd = &ATTACHMENT(key)->client_fd;
    d->origin_fd = &ATTACHMENT(key)->origin_fd;
    d->status = &ATTACHMENT(key)->client.request.status;
    d->wb = &ATTACHMENT(key)->write_buffer;
}

static unsigned request_connect(struct selector_key *key, struct request_st *d)
{
    bool error = false;
    bool fd_registered = false;
    struct socks5 *data = ATTACHMENT(key);
    int *fd = d->origin_fd;

    if(*fd != -1) { // si fd es distinto de -1 es porque hubo antes una conexión fallida
        fd_registered = true;

        if(close(*fd) == -1) {
            error = true;
            goto finally;
        }
    }

    unsigned ret = REQUEST_CONNECTING;
    *fd = socket(data->origin_domain, SOCK_STREAM, 0);
    if (*fd == -1)
    {
        error = true;
        goto finally;
    }

    if (selector_fd_set_nio(*fd) == -1)
    {
        goto finally;
    }

    if (connect(*fd, (const struct sockaddr *)&data->origin_addr,
                data->origin_addr_len) == -1)
    {

        if (errno == EINPROGRESS)
        {
            // hay que esperar a la conexión

            // dejamos de pollear el socket del cliente
            selector_status st = selector_set_interest_key(key, OP_NOOP);
            if (st != SELECTOR_SUCCESS)
            {
                error = true;
                goto finally;
            }

            // esperamos la conexión en el nuevo socket
            if(!fd_registered) {
                st = selector_register(key->s, *fd, &socks5_handler, OP_WRITE, key->data);
            }
            else {
                st = selector_set_interest(key->s, *fd, OP_WRITE);
            }

            if (st != SELECTOR_SUCCESS)
            {
                error = true;
                goto finally;
            }
        }
        else
        {
            // If connection is unsuccessful, send error to user
            data->client.request.status = errno_to_socks(errno);
            if (-1 != request_marshal(data->client.request.wb, data->client.request.status, data->client.request.request.dest_addr_type, data->client.request.request.dest_addr, data->client.request.request.dest_port))
            {
                selector_set_interest(key->s, data->client_fd, OP_WRITE);
                selector_status st = selector_register(key->s, *fd, &socks5_handler, OP_NOOP, key->data); // registro el nuevo fd pero lo seteo en NOOP porque no se pudo establecer la conexión
                if (st != SELECTOR_SUCCESS)
                {
                    error = true;
                    goto finally;
                }
                
                ret = REQUEST_WRITE;
            }
            else {
                error = true;
            }
            ATTACHMENT(key)->socks_info.status = data->client.request.status;   
            goto finally;
        }
    }

finally:
    return error ? ERROR : ret;
}

// la conexión ha sido establecida (o falló), parsear respuesta
static unsigned request_connecting(struct selector_key *key)
{
    int error;
    socklen_t len = sizeof(error);
    unsigned ret = REQUEST_CONNECTING;

    struct socks5 *data = ATTACHMENT(key);
    int *fd = data->orig.conn.origin_fd;
    if (getsockopt(*fd, SOL_SOCKET, SO_ERROR, &error, &len) == 0)
    {
        //Escribirle en el buffer de escritura al cliente
        selector_set_interest(key->s, *data->orig.conn.client_fd, OP_WRITE);
        
        if (error == 0)
        {
            data->client.request.status = status_succeeded;
            set_historical_conections(get_historical_conections() +1);
        }
        else {
            data->client.request.status = errno_to_socks(error);

            if(SELECTOR_SUCCESS != selector_set_interest_key(key, OP_NOOP)) {
                return ERROR;
            }

            ATTACHMENT(key)->socks_info.status = data->client.request.status;
            log_access(&ATTACHMENT(key)->socks_info);
            return REQUEST_RESOLV;
        }

        if (-1 != request_marshal(data->client.request.wb, data->client.request.status, data->client.request.request.dest_addr_type, data->client.request.request.dest_addr, data->client.request.request.dest_port))
        {
            selector_set_interest(key->s, *data->orig.conn.origin_fd, OP_READ);
            
            ret = REQUEST_WRITE;
        }
        else {
            ret = ERROR;
        }
        ATTACHMENT(key)->socks_info.status = data->client.request.status;    
    }

    return ret;
}

////////////////////////////////////////