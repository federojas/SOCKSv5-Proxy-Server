#include <string.h>
#include <arpa/inet.h>
#include "request_parser.h"


// TODO: mejorar estilo del codigo
static void remaining_set(request_parser *p, const int remainingBytes) {
    p->readBytes = 0;
    p->totalBytes = remainingBytes;
}

static int remaining_is_done(request_parser *p) {
    return p->readBytes >= p->totalBytes;
}

static request_state version(request_parser *p, const uint8_t c) {
    request_state next_state;
    switch(c) {
        case SOCKS5_VERSION:
            next_state = REQUEST_CMD;
            break;
        default:
            next_state = REQUEST_TRAP_UNSUPPORTED_VERSION;
            break;
    }
    return next_state;
}

static request_state cmd(request_parser *p, const uint8_t c) {
    // TODO: COMANDO INVALIDO 
    p->request->cmd = c;
    return REQUEST_RSV;
}

/* La cantidad de bytes que tendremos que leer
*  al pasar al proximo estado dependerá
*  del tipo de dirección, y tendremos que setear
*  el sockaddr correspondiente
*/
static request_state atyp(request_parser *p, const uint8_t c) {
    request_state next_state;

    // TODO: ADDRTYPE INVALIDO
    p->request->dest_addr_type = c;
    switch(c) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            remaining_set(p,IPV4_LENGTH);
            memset(&(p->request->dest_addr.ipv4), 0, sizeof(p->request->dest_addr.ipv4));
            p->request->dest_addr.ipv4.sin_family = AF_INET;
            next_state = REQUEST_DSTADDR;
            break;
        case SOCKS5_REQ_ADDRTYPE_IPV6:
            remaining_set(p,IPV6_LENGTH);
            memset(&(p->request->dest_addr.ipv6), 0, sizeof(p->request->dest_addr.ipv6));
            p->request->dest_addr.ipv6.sin6_family = AF_INET6;
            next_state = REQUEST_DSTADDR;
            break;
        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            next_state = REQUEST_DSTADDR_FQDN;
            break;
        default:
            next_state = REQUEST_TRAP_UNSUPPORTED_ATYP;
            break;
    }
    return next_state;
}

/* el byte recibido nos indica la long del fqdn */
static request_state dstaddr_fqdn(request_parser *p, const uint8_t c) {
    remaining_set(p,c);
    p->request->dest_addr.fqdn[p->totalBytes-1] = 0;
    return REQUEST_DSTADDR;
}

static request_state dstaddr(request_parser *p, const uint8_t c) {
    request_state next_state;
    p->request->dest_addr_type = c;
    switch(p->request->dest_addr_type) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            p->request->dest_addr.ipv4.sin_addr.s_addr = (p->request->dest_addr.ipv4.sin_addr.s_addr << 8) + c;
            p->readBytes++;
            // finalice la lectura y pasamos al puerto o seguimos
            if(remaining_is_done(p)) {
                p->request->dest_addr.ipv4.sin_addr.s_addr = htonl(p->request->dest_addr.ipv4.sin_addr.s_addr);
            }
            break;
        case SOCKS5_REQ_ADDRTYPE_IPV6:
            ((uint8_t *)&(p->request->dest_addr.ipv6.sin6_addr))[p->readBytes++] = c; 
            // no necesito una func como htonl porque struct in6_addr se representa como uint8_t u6_addr8[16];
            break;
        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            p->request->dest_addr.fqdn[p->readBytes++] = c;
            break;
        default:
            // con cualquier otro caso pasamos al trampa
            next_state = REQUEST_TRAP;
            break;
    }

    // termine la lectura, pasamos al puerto, sino seguimos en el mismo state
    if(remaining_is_done(p)) {
        remaining_set(p,PORT_LENGTH);
        p->request->dest_port = 0;
        next_state = REQUEST_DSTPORT;
    } else {
        next_state = REQUEST_DSTADDR;
    }
    return next_state;
}

static request_state dstport(request_parser * p, uint8_t c) {
    request_state next_state = REQUEST_DSTPORT;
    ((uint8_t *)&(p->request->dest_port))[p->readBytes++] = c; 
    if(remaining_is_done(p)) {
        p->request->dest_port = htons(p->request->dest_port);
        next_state = REQUEST_DONE;
    } 
    return next_state;
}

void request_parser_init(request_parser *p) {
    p->current_state = REQUEST_VERSION;
}

request_state request_parser_feed(request_parser *p, uint8_t byte) {
    request_state next;
    switch (p->current_state)
    {
        case REQUEST_VERSION:
            next = version(p,byte);
            break;
        case REQUEST_CMD:
            next = cmd(p,byte);
            break;
        case REQUEST_RSV:
            next = REQUEST_ATYP;
            break;
        case REQUEST_ATYP:
            next = atyp(p,byte);
            break;
        case REQUEST_DSTADDR_FQDN:
            next = dstaddr_fqdn(p,byte);
            break;
        case REQUEST_DSTADDR:
            next = dstaddr(p,byte);
            break;
        case REQUEST_DSTPORT:
            next = dstport(p,byte);
            break;
        case REQUEST_DONE:
            next = p->current_state;
            break;
        default:
            next = REQUEST_TRAP;
            break;
    }

    return p->current_state = next;
}


request_state request_parser_consume(buffer *b, request_parser *p, bool *errored) {

    uint8_t byte;
    while(!request_parser_is_done(p->current_state, errored) && buffer_can_read(b)) {
        byte = buffer_read(b);
        request_parser_feed(p, byte); 
    }

    return request_parser_is_done(p->current_state, errored);
}

bool request_parser_is_done(enum request_state state, bool *errored) {

    if(errored != NULL)
        *errored = false;
    switch(state) {

        case REQUEST_DONE:
            return true;
        break;

        case REQUEST_VERSION:
        case REQUEST_CMD:
        case REQUEST_RSV:
        case REQUEST_ATYP:
        case REQUEST_DSTADDR_FQDN:
        case REQUEST_DSTADDR:
        case REQUEST_DSTPORT:
            return false;
            break;
        default:
            if(errored != NULL)
                *errored = true;
            return true;
            break;
    }
}

// TODO: Mejorar los errores (EERNO.H clase 31/5 2:52:35)

char * request_parser_error_report(request_state state){
    switch(state) {

        case REQUEST_DONE:
        case REQUEST_VERSION:
        case REQUEST_CMD:
        case REQUEST_RSV:
        case REQUEST_ATYP:
        case REQUEST_DSTADDR_FQDN:
        case REQUEST_DSTADDR:
        case REQUEST_DSTPORT:
            return "Request-parser: no error";
        break;
        default:

            return "Request-parser: on trap state";
        break;
    }
        
}
