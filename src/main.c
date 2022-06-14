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

#define PORT 1080
#define DEST_PORT 8888
#define MAX_PENDING_CONN 20
#define MAX_ADDR_BUFFER 128
#define SELECTOR_SIZE 1024

static bool done = false;
extern struct socks5args socks5args;
// static char addrBuffer[MAX_ADDR_BUFFER];

static int build_TCP_passive_socket(addr_type addr_type, bool manager_socket);

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

// TODO: este handler no se si esta bien
void read_handler(struct selector_key *key){
    char buffer[1024]; // Buffer for echo string
	// Receive message from client
	ssize_t numBytesRcvd = recv(key->fd, buffer, 1024, 0);
	if (numBytesRcvd < 0) {
		log_print(LOG_ERROR, "recv() failed");
		// return -1;   // TODO definir codigos de error
	}

    // TODO: Me falta registrarlo para escritura una vez que ya lei todo?
}


void write_handler(struct selector_key * key){
    // struct buffer * buffer = (struct buffer * )key->data;
    // size_t bytesToSend = buffer->len - buffer->from;
	// if (bytesToSend > 0) {  // Puede estar listo para enviar, pero no tenemos nada para enviar
	// 	log_print(INFO, "Trying to send %zu bytes to socket %d\n", bytesToSend, socket);
	// 	size_t bytesSent = send(socket, buffer->buffer + buffer->from,bytesToSend,  MSG_DONTWAIT); 
	// 	log_print(INFO, "Sent %zu bytes\n", bytesSent);

	// 	if ( bytesSent < 0) {
	// 		// Esto no deberia pasar ya que el socket estaba listo para escritura
	// 		// TODO: manejar el error
	// 		// log_print(FATAL, "Error sending to socket %d", socket);
	// 	} else {
	// 		size_t bytesLeft = bytesSent - bytesToSend;

	// 		// Si se pudieron mandar todos los bytes limpiamos el buffer y sacamos el fd para el select
	// 		if ( bytesLeft == 0) {
	// 			clear(buffer);
	// 			// TOODO : ME FALTA SACAR EL FD DEL SELECTOR
	// 		} else {
	// 			buffer->from += bytesSent;
	// 		}
	// 	}
	// }
}



// Estos serian los handlers de los sockets activos que abri con 
// el destino
// static fd_handler activeSocketHandler = {
//     .handle_read = &readHandler,
//     .handle_write = &writeHandler,
//     .handle_block = NULL,
//     .handle_close = NULL
// };


////////////////////// OLD MAIN JUST IN CASE

// unsigned port = PORT;

// if(argc == 1) {
    //     // utilizamos el default
    // } else if(argc == 2) {
    //     char *end     = 0;
    //     const long sl = strtol(argv[1], &end, 10);

    //     if (end == argv[1] || '\0' != *end 
    //        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
    //        || sl < 0 || sl > USHRT_MAX) {
    //         fprintf(stderr, "port should be an integer: %s\n", argv[1]);
    //         return 1;
    //     }
    //     port = sl;
    // } else {
    //     fprintf(stderr, "Usage: %s <port>\n", argv[0]);
    //     return 1;
    // }


    // struct sockaddr_in addr;
    // memset(&addr, 0, sizeof(addr));
    // addr.sin_family      = AF_INET;
    // addr.sin_addr.s_addr = htonl(INADDR_ANY);
    // addr.sin_port        = htons(port);

    // const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // if(server < 0) {
    //     err_msg = "unable to create socket";
    //     goto finally;
    // }

    // fprintf(stdout, "Listening on TCP port %d\n", port);

    // // man 7 ip. no importa reportar nada si falla.
    // setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    // if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
    //     err_msg = "unable to bind socket";
    //     goto finally;
    // }

    // if (listen(server, MAX_PENDING_CONN) < 0) {
    //     err_msg = "unable to listen";
    //     goto finally;
    // }
    

    // if(selector_fd_set_nio(server) == -1) {
    //     err_msg = "getting server socket flags";
    //     goto finally;
    // }
    
    // ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    // if(ss != SELECTOR_SUCCESS) {
    //     err_msg = "registering fd";
    //     goto finally;
    // }

int main(const int argc, char **argv) {

    close(0);

    const char* err_msg = NULL;
    int ret = 0;
    address_data origin_address;
    int current_sock_fd = -1;
    int proxy_socks5[2], proxy_socks5_size =0;
    int server_manager[2], server_manager_size = 0;
    parse_args(argc, argv, &socks5args);

    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    //Creando sockets pasivos IPv4 e IPv6 para el servidor proxy SOCKSv5

    current_sock_fd = build_TCP_passive_socket(ADDR_IPV4, false);
    if (current_sock_fd < 0) {
        log_print(DEBUG, "Unable to create passive IPv4 proxy");
    } else if (selector_fd_set_nio(current_sock_fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting SOCKSv5 server IPv4 socket as non blocking";
        goto finally;
    } else {
        proxy_socks5[proxy_socks5_size++] = current_sock_fd;
    }

    current_sock_fd = build_TCP_passive_socket(ADDR_IPV6, false);
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

    current_sock_fd = build_TCP_passive_socket(ADDR_IPV4, true);
    if (current_sock_fd < 0) {
        log_print(DEBUG, "Unable to create passive IPv4 proxy");
    } else if (selector_fd_set_nio(current_sock_fd) == -1) {
        perror("selector_fd_set_nio");
        err_msg = "Error getting server manager IPv4 socket as non blocking";
        goto finally;
    } else {
        server_manager[server_manager_size++] = current_sock_fd;
    }

    current_sock_fd = build_TCP_passive_socket(ADDR_IPV6, true);
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

    // registrar sigterm es util para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    //timeout

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

    //manager handler FALTA
    // const struct fd_handler manager = {
    //     .handle_read       = manager_passive_accept,
    //     .handle_write      = NULL,
    //     .handle_close      = NULL, // nada que liberar
    // };

    //Origen para selector
    origin_address.port = socks5args.origin_port;
    get_address_data(&origin_address, socks5args.origin_addr);

    for (int i = 0; i < proxy_socks5_size; i++) {
        ss = selector_register(selector, proxy_socks5[i], &socksv5, OP_READ, &origin_address);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Error registering SOCKSv5 server passive fd";
            goto finally;
        }
    }

    for (int i = 0; i < server_manager_size; i++) {
        ss = selector_register(selector, server_manager[i], &socksv5, OP_READ, NULL);
        if (ss != SELECTOR_SUCCESS) {
            err_msg = "Error registering server manager passive fd";
            goto finally;
        }
    }

    //ver timeout

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
        fprintf(stderr, "%s: %s\n", (err_msg == NULL) ? "": err_msg,
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


static int build_TCP_passive_socket(addr_type addr_type, bool manager_socket) {

    int new_socket;

    struct sockaddr_in addr;
    struct sockaddr_in6 addr_6;

    int network_flag = (addr_type == ADDR_IPV4) ? AF_INET : AF_INET6;
    int socket_type = SOCK_STREAM; //TCP socket
    int protocol = IPPROTO_TCP; //TCP socket

    int port = manager_socket ? socks5args.mng_port : socks5args.socks_port;
    char * string_addr = manager_socket ? socks5args.mng_addr : socks5args.socks_addr;

    // Default config, escuchar en server proxy y en manager

    if (strcmp(string_addr,"0.0.0.0") == 0 && addr_type == ADDR_IPV6 && !manager_socket
            && socks5args.socks_on_both ) {
        string_addr = "0::0";
    }

    if (strcmp(string_addr,"127.0.0.1") == 0 && addr_type == ADDR_IPV6 && manager_socket
            && socks5args.mng_on_both ) {
        string_addr = "::1";
    }

    new_socket = socket(network_flag, socket_type, protocol);
    if(new_socket < 0) {
        log_print(LOG_ERROR, "Unable to create passive socket");
        return -1;
    }

    // man 7 ip. no importa reportar nada si falla, solo reporto el error
    if(setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int)) < 0) {
        log_print(LOG_ERROR, "Unable to set socket options");
    }

    // Sockets ipv6 no acepta ipv4 
    // man 7 ip. no importa reportar nada si falla, solo reporto el error
    if (addr_type == ADDR_IPV6 && setsockopt(new_socket, IPPROTO_IPV6, IPV6_V6ONLY, &(int){ 1 }, sizeof(int)) < 0) {
        log_print(LOG_ERROR, "Unable to set socket options");
    }

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
        if (inet_pton(AF_INET6, string_addr, &addr_6.sin6_addr) <= 0) {
            log_print(DEBUG, "Address %s does not translate to IPv6", string_addr);
            close(new_socket);
            return -1;
        }
        if (bind(new_socket, (struct sockaddr *)&addr_6, sizeof(addr_6)) < 0) {

            log_print(LOG_ERROR, "Unable to bind socket");
            close(new_socket);
            return -1;
        }
    }

    if (!manager_socket && listen(new_socket, MAX_PENDING_CONN) < 0) {
        log_print(LOG_ERROR, "Unable to listen socket");
        close(new_socket);
        return -1;
    }
    else {
        log_print(INFO, "Waiting for new %s %s connection on socket with fd: %d", addr_type == ADDR_IPV4 ? "IPv4":"IPv6", manager_socket ? "SOCKSv5":"manager", new_socket);
    }

    return new_socket;
}