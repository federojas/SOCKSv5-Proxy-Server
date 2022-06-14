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

#define PORT 1080
#define DEST_PORT 8888
#define MAX_PENDING_CONN 20
#define MAX_ADDR_BUFFER 128

static bool done = false;
extern struct socks5args socks5args;
// static char addrBuffer[MAX_ADDR_BUFFER];

static void
sigterm_handler(const int signal) {
    printf("signal %d, cleaning up and exiting\n",signal);
    done = true;
}

struct buffer {
	char * buffer;
	size_t len;     // longitud del buffer
	size_t from;    // desde donde falta escribir
};

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

int main(const int argc, char **argv) {
    unsigned port = PORT;

    if(argc == 1) {
        // utilizamos el default
    } else if(argc == 2) {
        char *end     = 0;
        const long sl = strtol(argv[1], &end, 10);

        if (end == argv[1] || '\0' != *end 
           || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
           || sl < 0 || sl > USHRT_MAX) {
            fprintf(stderr, "port should be an integer: %s\n", argv[1]);
            return 1;
        }
        port = sl;
    } else {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        return 1;
    }

    // no tenemos nada que leer de stdin
    close(0);

    // parse_args(argc, argv, &socks5args);

    const char       *err_msg = NULL;
    selector_status   ss      = SELECTOR_SUCCESS;
    fd_selector selector      = NULL;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(port);

    const int server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server < 0) {
        err_msg = "unable to create socket";
        goto finally;
    }

    fprintf(stdout, "Listening on TCP port %d\n", port);

    // man 7 ip. no importa reportar nada si falla.
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &(int){ 1 }, sizeof(int));

    if(bind(server, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
        err_msg = "unable to bind socket";
        goto finally;
    }

    if (listen(server, MAX_PENDING_CONN) < 0) {
        err_msg = "unable to listen";
        goto finally;
    }

    // registrar sigterm es Ãºtil para terminar el programa normalmente.
    // esto ayuda mucho en herramientas como valgrind.
    signal(SIGTERM, sigterm_handler);
    signal(SIGINT,  sigterm_handler);

    if(selector_fd_set_nio(server) == -1) {
        err_msg = "getting server socket flags";
        goto finally;
    }
    const struct selector_init conf = {
        .signal = SIGALRM,
        .select_timeout = {
            .tv_sec  = 10,
            .tv_nsec = 0,
        },
    };
    if(0 != selector_init(&conf)) {
        err_msg = "initializing selector";
        goto finally;
    }

    selector = selector_new(1024);
    if(selector == NULL) {
        err_msg = "unable to create selector";
        goto finally;
    }

    const struct fd_handler socksv5 = {
        .handle_read       = socksv5_passive_accept,
        .handle_write      = NULL,
        .handle_close      = NULL, // nada que liberar
    };
    ss = selector_register(selector, server, &socksv5, OP_READ, NULL);
    if(ss != SELECTOR_SUCCESS) {
        err_msg = "registering fd";
        goto finally;
    }
    for(;!done;) {
        err_msg = NULL;
        ss = selector_select(selector);
        if(ss != SELECTOR_SUCCESS) {
            err_msg = "serving";
            goto finally;
        }
    }
    if(err_msg == NULL) {
        err_msg = "closing";
    }

    int ret = 0;
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

    //cerrar los proxy socks

    socksv5_pool_destroy();

    if(server >= 0) {
        close(server);
    }
    return ret;
}