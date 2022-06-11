#ifndef SOCKS5_REQUEST_PARSER_H_
#define SOCKS5_REQUEST_PARSER_H_

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "buffer.h"

static const int IPV4_LENGTH = 4;
static const int IPV6_LENGTH = 16;
static const int PORT_LENGTH = 2;

// Comandos validos (creo que en realidad solo vamos a usar CONNECT)
enum socks5_cmd {
    SOCKS5_REQ_CMD_CONNECT = 0x01,
    SOCKS5_REQ_CMD_BIND = 0x02,
    SOCKS5_REQ_CMD_ASSOCIATE = 0x03,
};

// Tipos de direcciones validos
enum socks5_addr_type {
    SOCKS5_REQ_ADDRTYPE_IPV4 = 0x01,
    SOCKS5_REQ_ADDRTYPE_IPV6 = 0x04,
    SOCKS5_REQ_ADDRTYPE_DOMAIN = 0x03,
};

/* Usamos union ya que se usara solo una de estas opciones a la vez */
union socks5_addr {
    char fqdn[0xFF];
    struct sockaddr_in ipv4;
    struct sockaddr_in6 ipv6;
};

/* Estructura de la request bien formada */
typedef struct socks5_request {
    enum socks5_cmd cmd;
    enum socks5_addr_type dest_addr_type;
    union socks5_addr dest_addr;
    /* no olvidar que está en byte order */
    in_port_t dest_port;
} socks5_request;

typedef enum request_state {
    REQUEST_VERSION,
    REQUEST_CMD,
    REQUEST_RSV,
    REQUEST_ATYP,
    REQUEST_DSTADDR_FQDN,
    REQUEST_DSTADDR,
    REQUEST_DSTPORT,
 
    REQUEST_DONE,
    
    // TODO: Diferenciar los estados de error para tener una mejor descripcion
    REQUEST_TRAP,
    REQUEST_TRAP_UNSUPPORTED_VERSION,
    REQUEST_TRAP_UNSUPPORTED_ATYP,
} request_state;

enum socks5_response_status {
    SOCKS5_STATUS_SUCCEED = 0x00,
    SOCKS5_STATUS_GENERAL_SERVER_FAILURE = 0x01,
    SOCKS5_STATUS_CONN_NOT_ALLOWED_BY_RULESET = 0x02,
    SOCKS5_STATUS_NETWORK_UNREACHABLE = 0x03,
    SOCKS5_STATUS_HOST_UNREACHABLE = 0x04,
    SOCKS5_STATUS_CONN_REFUSED = 0x05,
    SOCKS5_STATUS_TTL_EXPIRED = 0x06,
    SOCKS5_STATUS_CMD_NOT_SUPPORTED = 0x07,
    SOCKS5_STATUS_ADDRTYPE_NOT_SUPPORTED = 0x08,
};

typedef struct request_parser {
    struct socks5_request *request;
    enum request_state current_state;
    uint8_t totalBytes;
    uint8_t readBytes;
} request_parser;

void request_parser_init(request_parser *p);

enum request_state request_parser_feed(request_parser *p, uint8_t byte);

enum request_state request_parser_consume(buffer *b, request_parser *p, bool *errored);

bool request_parser_is_done(enum request_state state, bool *errored);

char * request_parser_error_report(enum request_state state);

#endif