// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <stdio.h>     /* for printf */
#include <stdlib.h>    /* for exit */
#include <limits.h>    /* LONG_MIN et al */
#include <string.h>    /* memset */
#include <errno.h>
#include <getopt.h>

#include "args.h"
#include "user_utils.h"

struct socks5_args socks5_args;

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

static
void user(char *s, struct user_info *user) {
    char *p = strchr(s, USER_PASS_DELIMETER);
    if(p == NULL) {
        fprintf(stderr, "Password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        if(user_registerd(s)) {
            fprintf(stderr, "Duplicate user specified\n");
            exit(1);
        }
        if(strlen(s) > MAX_CRED_SIZE || strlen(p) > MAX_CRED_SIZE) {
            fprintf(stderr, "Username or password specified too long, maximum length is 255 characters\n");
            exit(1);
        }
        strcpy(user->username,s);
        strcpy(user->password,p);
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
parse_args(const int argc, char **argv, struct socks5_args *args) {

    memset(args, 0, sizeof(*args));
    
    args->version = DEFAULT_VERSION_NUMBER;
    args->nusers = 0;

    args->socks_addr = DEFAULT_PROXY_ADDR;
    args->socks_addr6 = DEFAULT_PROXY_ADDR6;
    args->socks_port = DEFAULT_SOCKS_PORT;

    args->mng_addr   = DEFAULT_MNG_ADDR;
    args->mng_addr6   = DEFAULT_MNG_ADDR6;
    args->mng_port   = DEFAULT_MNG_PORT;

    args->spoofing = true;
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
                if(strchr(optarg, ':') != NULL)
                    args->socks_addr6 = optarg;
                else
                    args->socks_addr = optarg;
                break;
            case 'L':
                if(strchr(optarg, ':') != NULL)
                    args->mng_addr6 = optarg;
                else
                    args->mng_addr = optarg;
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
                    exit(1);
                } else {
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
                fprintf(stderr, "Unknown argument %d.\n", c);
                exit(1);
        }

    }
    if (optind < argc) {
        fprintf(stderr, "Argument not accepted: ");
        while (optind < argc) {
            fprintf(stderr, "%s ", argv[optind++]);
        }
        fprintf(stderr, "\n");
        exit(1);
    }
}



