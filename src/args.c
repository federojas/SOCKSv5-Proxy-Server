// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
#include <errno.h>
#include <getopt.h>
#include <limits.h> /* LONG_MIN et al */
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h> /* memset */

#include "args.h"
#include "user_utils.h"

struct socks5_args socks5_args;

static unsigned short port(const char *s) {
    char *end = 0;
    const long sl = strtol(s, &end, 10);

    if (end == s || '\0' != *end ||
        ((LONG_MIN == sl || LONG_MAX == sl) && ERANGE == errno) || sl < 0 ||
        sl > USHRT_MAX) {
        fprintf(stderr, "Port should in in the range of 1-65536: %s\n", s);
        exit(1);
        return 1;
    }
    return (unsigned short)sl;
}

static void user(char *s, struct user_info *user) {
    char *p = strchr(s, USER_PASS_DELIMETER);
    if (p == NULL) {
        fprintf(stderr, "Password not found\n");
        exit(1);
    } else {
        *p = 0;
        p++;
        if (user_registerd(s)) {
            fprintf(stderr, "Duplicate user specified\n");
            exit(1);
        }
        if (strlen(s) > MAX_CRED_SIZE || strlen(p) > MAX_CRED_SIZE) {
            fprintf(stderr, "Username or password specified too long, maximum "
                            "length is 255 characters\n");
            exit(1);
        }
        strcpy(user->username, s);
        strcpy(user->password, p);
    }
}

static void version(void) {
    fprintf(stderr, "SOCKSv5 server version: " DEFAULT_VERSION_NUMBER "\n"
                    "ITBA Protocolos de Comunicación 2022/1 -- Group 3\n"
                    "DOG SOFTWARE LICENSED PRODUCT\n");
}

static void usage(const char *progname) {
    fprintf(
        stderr,
        "Usage: %s [OPTION]...\n"
        "\n"
        "Commands: -l and -L can be used 2 times each to send both ipv4 and ipv6 addresses.\n"
        "Command: -u cand be used up to 10 times.\n\n"
        "   -h               Prints help info and finishes.\n"
        "   -l <SOCKS addr>  Adress (ipv4 or ipv6) where SOCKS server will "
        "serve.\n"
        "   -L <mng  addr>   Adress (ipv4 or ipv6) where server manager will "
        "serve.\n"
        "   -p <SOCKS port>  Port for incoming connection on SOCKS server.\n"
        "   -P <mng port>    Port for incoming connection on server manager\n"
        "   -u <name>:<pass> Username and password of SOCKS server allowed "
        "users.\n"
        "   -N               Turn off POP3 credential sniffing.\n"
        "   -v               Prints current version info and finishes.\n"
        "\n",
        progname);
    exit(1);
}

void parse_args(const int argc, char **argv, struct socks5_args *args) {

    memset(args, 0, sizeof(*args));

    args->version = DEFAULT_VERSION_NUMBER;
    args->nusers = 0;

    args->socks_addr = DEFAULT_PROXY_ADDR;
    args->socks_addr6 = DEFAULT_PROXY_ADDR6;
    args->socks_port = DEFAULT_SOCKS_PORT;

    args->mng_addr = DEFAULT_MNG_ADDR;
    args->mng_addr6 = DEFAULT_MNG_ADDR6;
    args->mng_port = DEFAULT_MNG_PORT;

    char *token_env = getenv(DOG_TOKEN);
    if (token_env == NULL || strlen(token_env) != TOKEN_SIZE) {
        fprintf(
            stderr,
            "SOCKSv5: ERROR, erroneous or unexistent DOG_TOKEN env variable\n");
        fprintf(stderr,
                "The token name must be DOG_TOKEN and its value 4 bytes\n");
        exit(1);
    }
    args->manager_token = strtoul(token_env, NULL, 10);

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
            if (strchr(optarg, ':') != NULL) 
                args->socks_addr6 = optarg;
            else
                args->socks_addr = optarg;
            break;
        case 'L':
            if (strchr(optarg, ':') != NULL)
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
            args->mng_port = port(optarg);
            break;
        case 'u':
            if (args->nusers >= MAX_USERS) {
                fprintf(
                    stderr,
                    "\n\nMaximun number of command line users reached: %d.\n",
                    MAX_USERS);
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
