#ifndef ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8
#define ARGS_H_kFlmYm1tW9p5npzDr2opQJ9jM8

#include <stdbool.h>

#define MAX_USERS 10
#define MAX_CRED_SIZE 255

struct user_info {
    char * username;
    char * password;
} user_info;


struct socks5args {
    char           *socks_addr;
    unsigned short  socks_port;

    char *          mng_addr;
    unsigned short  mng_port;

    bool            disectors_enabled;
    struct user_info    users[MAX_USERS];
};

/**
 * Interpreta la linea de comandos (argc, argv) llenando
 * args con defaults o la seleccion humana. Puede cortar
 * la ejecuciÃ³n.
 */
void 
parse_args(const int argc, char **argv, struct socks5args *args);

int user_registerd(char * user, char * pass);

#endif
