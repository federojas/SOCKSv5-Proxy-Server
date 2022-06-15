#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "args.h"

struct socks5args socks5args;

static unsigned short
port(const char *s) {
     char *end     = 0;
     const long sl = strtol(s, &end, 10);

     if (end == s|| '\0' != *end
        || ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno)
        || sl < 0 || sl > USHRT_MAX) {
         fprintf(stderr, "Port should in in the range of 1-65536: %s\n", s);
         exit(1);
         return 1;
     }
     return (unsigned short)sl;
}

static void
user(char *s, struct user_info *user) {
    int absent = 0;
    char *p = strchr(s, ':');
    if(p == NULL) {
        fprintf(stderr, "Password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        if(strlen(s) > 255 || strlen(p) > 255){
            fprintf(stderr, "Username or password specified too long, maximum length is 255 characters\n");
            exit(1);
        }
        //Buscar en users

        user->username = s;
        user->password = p;
        if(absent) {
            //Buscar en admin
        }
    }
}

static void
version(void) {
    fprintf(stderr, "Servidor SOCKSv5 version: " DEFAULT_VERSION_NUMBER "\n"
                    "ITBA Protocolos de ComunicaciÃ³n 2022/1 -- Grupo 3\n"
                    "DOG SOFTWARE LICENSED PRODUCT\n");
}

static void
usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "   -h               Imprime la ayuda y termina.\n"
        "   -l <SOCKS addr>  DirecciÃ³n donde servirÃ¡ el proxy SOCKS.\n"
        "   -L <conf  addr>  DirecciÃ³n donde servirÃ¡ el servicio de management.\n"
        "   -p <SOCKS port>  Puerto entrante conexiones SOCKS.\n"
        "   -P <conf port>   Puerto entrante conexiones configuracion\n"
        "   -u <name>:<pass> Usuario y contraseÃ±a de usuario que puede usar el proxy. Hasta 10.\n"
        "   -N               Deshabilitar spoofing de contraseÃ±as sobre POP3.\n"
        "   -v               Imprime informaciÃ³n sobre la versiÃ³n versiÃ³n y termina.\n"
        "\n",
        progname);
    exit(1);
}

void 
parse_args(const int argc, char **argv, struct socks5args *args) {

    memset(args, 0, sizeof(*args)); // sobre todo para setear en null los punteros de users
    
    args->version = DEFAULT_VERSION_NUMBER;
    args->nusers = 0;

    args->socks_addr = DEFAULT_PROXY_ADDR;
    args->socks_port = DEFAULT_SOCKS_PORT;
    args->socks_on_both = true;

    args->mng_addr   = DEFAULT_MNG_ADDR;
    args->mng_port   = DEFAULT_MNG_PORT;
    args->mng_on_both = true;
    
    args->spoofing = false;
    args->authentication = false;
 
    int c;

    while (true) {

        c = getopt(argc, argv, "hl:L:Np:P:u:v");
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(argv[0]);
                break;
            case 'l':
                args->socks_addr = optarg;
                args->socks_on_both = false;
                break;
            case 'L':
                args->mng_addr = optarg;
                args->mng_on_both = false;
                break;
            case 'N':
                args->spoofing = false;
                break;
            case 'p':
                args->socks_port = port(optarg);
                break;
            case 'P':
                args->mng_port   = port(optarg);
                break;
            case 'u':
                if(args->nusers >= MAX_USERS) {
                    fprintf(stderr, "\n\nMaximun number of command line users reached: %d.\n", MAX_USERS);
                    //free_args(); TODO FREE USUSARIOS Y ADMINS Y EL ARGS
                    exit(1);
                } else {
                    //COMO MANEJAMOS ADMINS??????
                    user(optarg, args->users + args->nusers);
                    args->nusers++;
                    args->authentication = true;
                }
                break;
            case 'v':
                version();
                exit(0);
                break;
            default:
                fprintf(stderr, "unknown argument %d.\n", c);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}


bool user_registerd(char * user, char * pass) {
    for(int i = 0; i < socks5args.nusers; i++ ) {
        if(strcmp(user, socks5args.users[i].username) == 0 && strcmp(pass, socks5args.users[i].password) == 0)
            return true;
    }
    return false;
}
