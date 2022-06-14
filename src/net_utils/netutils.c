#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <unistd.h>
#include <arpa/inet.h>

#include "netutils.h"

#define N(x) (sizeof(x)/sizeof((x)[0]))

extern const char *
sockaddr_to_human(char *buff, const size_t buffsize,
                  const struct sockaddr *addr) {
    if(addr == 0) {
        strncpy(buff, "null", buffsize);
        return buff;
    }
    in_port_t port;
    void *p = 0x00;
    bool handled = false;

    switch(addr->sa_family) {
        case AF_INET:
            p    = &((struct sockaddr_in *) addr)->sin_addr;
            port =  ((struct sockaddr_in *) addr)->sin_port;
            handled = true;
            break;
        case AF_INET6:
            p    = &((struct sockaddr_in6 *) addr)->sin6_addr;
            port =  ((struct sockaddr_in6 *) addr)->sin6_port;
            handled = true;
            break;
    }
    if(handled) {
        if (inet_ntop(addr->sa_family, p,  buff, buffsize) == 0) {
            strncpy(buff, "unknown ip", buffsize);
            buff[buffsize - 1] = 0;
        }
    } else {
        strncpy(buff, "unknown", buffsize);
    }

    strncat(buff, ":", buffsize);
    buff[buffsize - 1] = 0;
    const size_t len = strlen(buff);

    if(handled) {
        snprintf(buff + len, buffsize - len, "%d", ntohs(port));
    }
    buff[buffsize - 1] = 0;

    return buff;
}

int
sock_blocking_write(const int fd, buffer *b) {
        int  ret = 0;
    ssize_t  nwritten;
	 size_t  n;
	uint8_t *ptr;

    do {
        ptr = buffer_read_ptr(b, &n);
        nwritten = send(fd, ptr, n, MSG_NOSIGNAL);
        if (nwritten > 0) {
            buffer_read_adv(b, nwritten);
        } else /* if (errno != EINTR) */ {
            ret = errno;
            break;
        }
    } while (buffer_can_read(b));

    return ret;
}

int
sock_blocking_copy(const int source, const int dest) {
    int ret = 0;
    char buf[4096];
    ssize_t nread;
    while ((nread = recv(source, buf, N(buf), 0)) > 0) {
        char* out_ptr = buf;
        ssize_t nwritten;
        do {
            nwritten = send(dest, out_ptr, nread, MSG_NOSIGNAL);
            if (nwritten > 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else /* if (errno != EINTR) */ {
                ret = errno;
                goto error;
            }
        } while (nread > 0);
    }
    error:

    return ret;
}

void get_address_data(address_data *address, const char * ip) {

    memset(&(address->addr_storage.address_storage), 0, sizeof(address->addr_storage.address_storage));
    address->addr_type = ADDR_IPV4;
    address->domain = AF_INET;
    address->addr_len = sizeof(struct sockaddr_in);

    struct sockaddr_in try_ipv4;
    memset(&(try_ipv4), 0, sizeof(try_ipv4));
    try_ipv4.sin_family = AF_INET;
    int result = 0;

    //pruebo IPv4
    if ((result = inet_pton(AF_INET, ip, &try_ipv4.sin_addr.s_addr)) <= 0) {

        //cambio a IPv6 si no era IPv4
        address->addr_type = ADDR_IPV6;
        address->domain = AF_INET6;
        address->addr_len = sizeof(struct sockaddr_in6);

        struct sockaddr_in6 try_ipv6;
        memset(&(try_ipv6), 0, sizeof(try_ipv6));
        try_ipv6.sin6_family = AF_INET6;

        if ((result = inet_pton(AF_INET6, ip, &try_ipv6.sin6_addr.s6_addr)) <= 0) {
            
            // es un dominio pues no es ni IPv4 ni IPv6
            memset(&(address->addr_storage.address_storage), 0, sizeof(address->addr_storage.address_storage));
            address->addr_type = ADDR_DOMAIN;
            memcpy(address->addr_storage.fqdn, ip, strlen(ip));
            return;
        }
        try_ipv6.sin6_port = htons(address->port);
        memcpy(&address->addr_storage.address_storage, &try_ipv6, address->addr_len);
        return;
    }
    try_ipv4.sin_port = htons(address->port);
    memcpy(&address->addr_storage.address_storage, &try_ipv4, address->addr_len);
    return ;
}

