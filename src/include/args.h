#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include "statistics.h"

#define MAX_USERS 10
#define MAX_CRED_SIZE 255

#define DEFAULT_MNG_PORT 8080
#define DEFAULT_SOCKS_PORT 1080
#define DEFAULT_VERSION_NUMBER "1.0"
#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_PROXY_ADDR "0.0.0.0"

typedef struct user_info {
    char * username;
    char * password;
} user_info;


struct socks5args {
    char           *socks_addr;
    unsigned short  socks_port;
    bool            socks_on_both;

    char *          mng_addr;
    unsigned short  mng_port;
    bool            mng_on_both;
    
    int             nusers;
    char *          version;
    struct user_info users[MAX_USERS];
    struct socks5Stats stats;
};


/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void parse_args(const int argc, char **argv, struct socks5args *args);

bool user_registerd(char * user, char * pass);

#endif
