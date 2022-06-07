#include <string.h>
#include <arpa/inet.h>
#include "request_parser.h"


// TODO: mejorar estilo del codigo

static void remaining_set(request_parser *p, const int remainingBytes) {
    p->totalBytes = 0;
    p->remainingBytes = remainingBytes;
}

static int remaining_is_done(request_parser *p) {
    return p->totalBytes >= p->remainingBytes;
}

static request_state version(request_parser *p, const uint8_t c) {
    request_state next_state;
    switch(c) {
        case SOCKS5_VERSION:
            next_state = REQUEST_CMD;
            break;
        default:
            next_state = REQUEST_TRAP;
            break;
    }
    return next_state;
}

static request_state cmd(request_parser *p, const uint8_t c) {
    p->request->cmd = c;
    return REQUEST_RSV;
}

static request_state atyp(request_parser *p, const uint8_t c) {
    request_state next_state;
    p->request->dest_addr_type = c;
    switch(c) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            remaining_set(p,4);
            memset(&(p->request->dest_addr.ipv4), 0, sizeof(p->request->dest_addr.ipv4));
            p->request->dest_addr.ipv4.sin_family = AF_INET;
            next_state = REQUEST_DSTADDR;
            break;
        case SOCKS5_REQ_ADDRTYPE_IPV6:
            remaining_set(p,16);
            memset(&(p->request->dest_addr.ipv6), 0, sizeof(p->request->dest_addr.ipv6));
            p->request->dest_addr.ipv6.sin6_family = AF_INET6;
            next_state = REQUEST_DSTADDR;
            break;
        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            next_state = REQUEST_DSTADDR_FQDN;
            break;
        default:
            next_state = REQUEST_TRAP;
            break;
    }
    return next_state;
}