#ifndef __logger_h_
#define __logger_h_

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <limits.h>  /* LONG_MIN et al */
#include <stdio.h>   /* for printf */
#include <stdlib.h>  /* for exit */
#include <string.h>  /* memset */
#include <sys/socket.h> // socket
#include <sys/types.h>  // socket
#include <stdarg.h> //para el parametro ...


typedef enum {DEBUG=0, INFO, LOG_ERROR, FATAL} LOG_LEVEL;

extern LOG_LEVEL current_level;
extern bool error_flag;

/**
*  Minimo nivel de log a registrar. Cualquier llamada a log con un nivel mayor a newLevel sera ignorada
**/
void setLogLevel(LOG_LEVEL newLevel);

void log_print(LOG_LEVEL level, const char *fmt, ...);


// Debe ser una macro para poder obtener nombre y linea de archivo. 
/*
char * levelDescription(LOG_LEVEL level);

#define log_print(level, fmt, ...)   {if(level >= current_level) {\
	fprintf (stderr, "%s: %s:%d, ", levelDescription(level), __FILE__, __LINE__); \
	fprintf(stderr, fmt, ##__VA_ARGS__); \
	fprintf(stderr,"\n"); }\
	if ( level==FATAL) exit(1);}
*/

// struct log_info {
//     uint8_t method;
//     struct usr user_info;
//     enum socks_reply_status status;
//     enum socks_atyp atyp;
//     struct sockaddr_storage client_addr;
//     union socks_addr dest_addr;
//     in_port_t dest_port;

//     //Sniffer
//     char *user;
//     char *passwd;
//     enum protocol protocol;
// };

#endif

