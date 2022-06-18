// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>   // socket
#include <sys/socket.h>  // socket
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "selector.h"
#include "logger.h"
#include "socksv5_nio.h"
#include "args.h"
#include "netutils.h"
#include "buffer.h"
#include "statistics.h"
#include "dog_manager.h"

#define PORT 1080
#define DEST_PORT 8888
#define MAX_PENDING_CONN 20
#define MAX_ADDR_BUFFER 128
#define SELECTOR_SIZE 1024

#define DEFAULT_SOCKS5_IPV4 "0.0.0.0"
#define DEFAULT_SOCKS5_IPV6 "0::0"
#define DEFAULT_MANAGER_IPV4 "127.0.0.1"
#define DEFAULT_MANAGER_IPV6 "::1"


static bool done = false;
extern struct socks5_args socks5_args;
extern struct socks5_stats socks5_stats;

static int build_passive_socket(addr_type addr_type, bool udp_socket);

    // TODO: Clean up function
static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

int main(const int argc, char **argv) {

    close(STDIN_FILENO);

    const char* err_msg = NULL;
    int ret = 0;
    int current_sock_fd = -1;
    int proxy_socks5[2], proxy_socks5_size =0;
    int server_manager[2], server_manager_size = 0;
    parse_args(argc, argv, &socks5_args);
    stats_init(&socks5_stats);
    
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    //Creando sockets pasivos IPv4 e IPv6 para el servidor proxy SOCKSv5

    current_sock_fd = build_passive_socket(ADDR_IPV4, false);
    if (current_sock_fd < 0) {
        log_print(DEBUG, "Unable to create passive IPv4 proxy");
    } else if (selector_fd_set_nio(current_sock_fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting SOCKSv5 server IPv4 socket as non blocking";
        goto finally;
    } else {
        proxy_socks5[proxy_socks5_size++] = current_sock_fd;
    }
    
    current_sock_fd = build_passive_socket(ADDR_IPV6, false);
    if (current_sock_fd < 0) {
        log_print(DEBUG, "Unable to create passive IPv6 proxy");
    } else if (selector_fd_set_nio(current_sock_fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting SOCKSv5 server IPv6 socket as non blocking";
        goto finally;
    } else {
        proxy_socks5[proxy_socks5_size++] = current_sock_fd;
    }


    if (proxy_socks5_size == 0) {
        log_print(FATAL, "Unable to create neither (IPv4 | IPv6) passive socket for SOCKSv5 server");
    }


    //Creando sockets pasivos IPv4 e IPv6 para el administrador del servidor proxy SOCKSv5
    
    current_sock_fd = build_passive_socket(ADDR_IPV4, true);
    if (current_sock_fd < 0) {
        log_print(DEBUG, "Unable to create passive IPv4 proxy");
    } else if (selector_fd_set_nio(current_sock_fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting server manager IPv4 socket as non blocking";
        goto finally;
    } else {
        server_manager[server_manager_size++] = current_sock_fd;
    }
    
    current_sock_fd = build_passive_socket(ADDR_IPV6, true);
    if (current_sock_fd < 0) {
        log_print(DEBUG, "Unable to create passive IPv6 proxy");
    } else if (selector_fd_set_nio(current_sock_fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting server manager IPv6 socket as non blocking";
        goto finally;
    } else {
        server_manager[server_manager_size++] = current_sock_fd;
    }

    if (server_manager_size == 0) {
        log_print(FATAL, "Unable to create neither (IPv4 | IPv6) passive socket for server manager");
    }
    
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };

    if(0 != selector_init(&conf)) {
        err_msg = "Unable to initialize selector";
        goto finally;
    }

    selector = selector_new(SELECTOR_SIZE);
    if(selector == NULL) {
        err_msg = "Unable to create selector";
        goto finally;
    }

    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    for (int i = 0; i < proxy_socks5_size; i++) {
        ss = selector_register(selector, proxy_socks5[i], &socksv5, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Error registering SOCKSv5 server passive fd";
            goto finally;
        }
    }

    const struct fd_handler manager = {
        .handle_read       = manager_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };

    for (int i = 0; i < server_manager_size; i++) {
        ss = selector_register(selector, server_manager[i], &manager, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Error registering server manager passive fd";
            goto finally;
        }
    }

    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            log_print(LOG_ERROR, "%s",selector_error(ss));
            err_msg = "Error serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "No error, closing";
    }

    
finally:
    if(ss != SELECTOR_SUCCESS) {
        fprintf(stderr, "%s: %s\n", err_msg,
                                  ss == SELECTOR_IO
                                      ? strerror(errno)
                                      : selector_error(ss));
        ret = 2;
    } else if(err_msg) {
        perror(err_msg);
        ret = 1;
    }
    if(selector != NULL) {
        selector_destroy(selector);
    }
    selector_close();

    for (int i = 0; i < proxy_socks5_size; i++){
        close(proxy_socks5[i]);
    }

    
    for (int i = 0; i < server_manager_size; i++){
        close(server_manager[i]);
    }
   

    socksv5_pool_destroy();

    return ret;
}

static int build_passive_socket(addr_type addr_type, bool udp_socket) {

    int new_socket;

    struct sockaddr_in addr;
    struct sockaddr_in6 addr_6;

    int network_flag = (addr_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    int socket_type = udp_socket ? SOCK_DGRAM : SOCK_STREAM;
    int protocol = udp_socket ? IPPROTO_UDP : IPPROTO_TCP;

    int port = udp_socket ? socks5_args.mng_port : socks5_args.socks_port;
    char * string_addr = udp_socket ? socks5_args.mng_addr : socks5_args.socks_addr;
    char * string_addr6 = udp_socket ? socks5_args.mng_addr6 : socks5_args.socks_addr6;

    new_socket = socket(network_flag, socket_type, protocol);
    if(new_socket < 0) {
        log_print(LOG_ERROR, "Unable to create passive socket");
        return -1;
    }

    if(!udp_socket && setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
        log_print(LOG_ERROR, "Unable to set socket options");
    }

    // Sockets ipv6 no acepta ipv4 
    if (addr_type == ADDR_IPV6 && setsockopt(new_socket, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) < 0) {
        log_print(LOG_ERROR, "Unable to set socket options");
    }

    log_print(INFO, "Listening on %s port %d", udp_socket ? "UDP" : "TCP", port);
    if (addr_type == ADDR_IPV4) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port =  htons(port);
        if (inet_pton(AF_INET, string_addr, &addr.sin_addr.s_addr) <= 0) {
            log_print(DEBUG, "Address %s does not translate to IPv4", string_addr);
            close(new_socket);
            return -1;
        }
        if (bind(new_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            log_print(LOG_ERROR, "Unable to bind socket");
            close(new_socket);
            return -1;
        }
    } else {
        memset(&addr_6, 0, sizeof(addr_6));
        addr_6.sin6_family = AF_INET6;
        addr_6.sin6_port = htons(port);
        if (inet_pton(AF_INET6, string_addr6, &addr_6.sin6_addr) <= 0) {
            log_print(DEBUG, "Address %s does not translate to IPv6", string_addr6);
            close(new_socket);
            return -1;
        }

        if (bind(new_socket, (struct sockaddr *)&addr_6, sizeof(addr_6)) < 0) {
            log_print(LOG_ERROR, "Unable to bind socket");
            close(new_socket);
            return -1;
        }
    }

    if (!udp_socket && listen(new_socket, MAX_PENDING_CONN) < 0) {
        log_print(LOG_ERROR, "Unable to listen socket");
        close(new_socket);
        return -1;
    }
    else {
        log_print(INFO, "Waiting for new %s %s connection on %s socket with address %s and fd: %d\n\n", addr_type == ADDR_IPV4 ? "IPv4":"IPv6", udp_socket ? "manager":"SOCKSv5", udp_socket ? "UDP":"TCP", addr_type == ADDR_IPV4 ? string_addr:string_addr6,  new_socket);
    }

    return new_socket;
}