#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>
#include "statistics.h"
#include "user_utils.h"
#define MAX_USERS 10
#define MAX_CRED_SIZE 255
#define USER_PASS_DELIMETER ':'

#define DEFAULT_MNG_PORT 8080
#define DEFAULT_SOCKS_PORT 1080
#define DEFAULT_VERSION_NUMBER "1"
#define DEFAULT_MNG_ADDR "127.0.0.1"
#define DEFAULT_MNG_ADDR6 "::1"
#define DEFAULT_PROXY_ADDR "0.0.0.0"
#define DEFAULT_PROXY_ADDR6 "0::0"
#define DOG_TOKEN "DOG_TOKEN"
#define TOKEN_SIZE 4

struct socks5_args {
    char *          socks_addr;
    char *          socks_addr6;
    unsigned short  socks_port;

    char *          mng_addr;
    char *          mng_addr6;
    unsigned short  mng_port;
    
    int             nusers;
    char *          version;
    struct user_info users[MAX_USERS];

    uint32_t        manager_token;
    bool            spoofing;
    bool            authentication;
};


/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void parse_args(const int argc, char **argv, struct socks5_args *args);

#endif
