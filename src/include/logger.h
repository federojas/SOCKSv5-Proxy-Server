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
#include "user_utils.h"
#include "netutils.h"
#include "request_parser.h"

#define DATE_SIZE 21

typedef enum {DEBUG=0, INFO, LOG_ERROR, FATAL} LOG_LEVEL;

typedef enum log_type {
    AUTH_LOG_DATA,
    POP3_LOG_DATA
} log_type;

typedef struct log_data {
    char date[DATE_SIZE];
    struct user_info user_info;
    struct sockaddr_storage client_addr;
    enum socks5_addr_type dest_addr_atyp;
    union socks5_addr dest_addr;
    in_port_t dest_port;
    enum socks5_response_status response_status;
    struct user_info sniffed_user_info;
} log_data;

extern LOG_LEVEL current_level;
extern bool error_flag;

void setLogLevel(LOG_LEVEL newLevel);

void log_print(LOG_LEVEL level, const char *fmt, ...);

void sign_in_print(log_data * log_data);

void pop3_sniffer_print(log_data * log_data);

#endif

