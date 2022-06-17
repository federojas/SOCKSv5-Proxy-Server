#include <time.h>
#include <stdio.h>
#include "logger.h"
#include "buffer.h"

LOG_LEVEL current_level = DEBUG;
bool error_flag = false;

#define DATE_FORMAT "%FT%TZ"
#define AUTH_FORMAT "%s\t%s\tA\t%s\t%s:%u\tstatus=%d\n"
#define NO_AUTH_FORMAT "%s\tA\t%s\t%s:%u\tstatus=%d\n"
#define POP3_SNIFF_FORMAT "%s\t%s\tP\tPOP3\t%s:%u\tsniffed credentials: %s:%s\tstatus=%d\n"

static void print_log_data(log_data * log_data, log_type type);
static void get_current_date_time(char * date);
static char* dest_to_human(enum socks5_addr_type dest_addr_atyp, union socks5_addr dest_addr);

void setLogLevel(LOG_LEVEL newLevel) {
	if ( newLevel >= DEBUG && newLevel <= FATAL )
	   current_level = newLevel;
}

char * levelDescription(LOG_LEVEL level) {
    static char * description[] = {"DEBUG", "INFO", "ERROR", "FATAL"};
    if (level < DEBUG || level > FATAL)
        return "";
    return description[level];
}


void log_print(LOG_LEVEL level, const char *fmt, ...) {
    if(level >= current_level) {
        fprintf (stderr, "%s: ", levelDescription(level)); 
        va_list arg; 
        va_start(arg, fmt); 
        vfprintf(stderr, fmt, arg);
        va_end(arg);
        fprintf(stderr,"\n"); 
    }
	if (level==FATAL) exit(1);
    if(level==LOG_ERROR) error_flag = true; 
}

void sign_in_print(log_data * log_data) {
    print_log_data(log_data, AUTH_LOG_DATA);

}

void pop3_sniffer_print(log_data * log_data) {
    print_log_data(log_data, POP3_LOG_DATA);
}

static void get_current_date_time(char * date) {
    time_t now = time(NULL);
    struct tm * time_info = localtime(&now);
    strftime(date, DATE_SIZE, DATE_FORMAT, time_info);
}

static char* dest_to_human(enum socks5_addr_type dest_addr_atyp, union socks5_addr dest_addr) {
    char * to_return = NULL; 
    switch (dest_addr_atyp) {
        case SOCKS5_REQ_ADDRTYPE_IPV4:
            to_return = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
            inet_ntop(AF_INET, &(((struct sockaddr_in *)&dest_addr.ipv4)->sin_addr), to_return, INET_ADDRSTRLEN);
        break;
        case SOCKS5_REQ_ADDRTYPE_IPV6:
            to_return = (char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&dest_addr.ipv6)->sin6_addr), to_return, INET6_ADDRSTRLEN);
        break;
        case SOCKS5_REQ_ADDRTYPE_DOMAIN:
            to_return = (char *)malloc((strlen(dest_addr.fqdn) + 1) * sizeof(char));
            strcpy(to_return, dest_addr.fqdn);
        break;
        default:
        break;
    }
    return to_return;
}

static void print_log_data(log_data * log_data, log_type type) {
    get_current_date_time(log_data->date);

    size_t string_addr_length = log_data->client_addr.ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char client_string_addr[string_addr_length];
    sockaddr_to_human(client_string_addr, string_addr_length, &log_data->client_addr);

    char * dest_string_addr = dest_to_human(log_data->dest_addr_atyp, log_data->dest_addr);
    uint8_t dest_port = ntohs(log_data->dest_port);


    switch(type) {
        case AUTH_LOG_DATA:
            if(log_data->username != NULL) {
                log_print(INFO, AUTH_FORMAT, log_data->date, log_data->username, client_string_addr, dest_string_addr, dest_port, log_data->response_status);
            }else {
                log_print(INFO, NO_AUTH_FORMAT, log_data->date, client_string_addr, dest_string_addr, dest_port, log_data->response_status);
            }
            
        break;

        case POP3_LOG_DATA:
            log_print(INFO, POP3_SNIFF_FORMAT, log_data->date, log_data->username,  dest_string_addr, dest_port, log_data->sniffed_user_info.username, log_data->sniffed_user_info.password, log_data->response_status);
        break;

        default:
        break;
    }

    free(dest_string_addr);
}