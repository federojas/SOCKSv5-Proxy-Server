#include "user_utils.h"
#include "args.h"
#include <string.h>

extern struct socks5_args socks5_args;

bool user_registerd(char *user) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (socks5_args.users[i].username != NULL &&
            strcmp(user, socks5_args.users[i].username) == 0)
            return true;
    }
    return false;
}

bool check_credentials(char *user, char *pass) {
    for (int i = 0; i < MAX_USERS; i++) {
        if (socks5_args.users[i].username != NULL &&
            strcmp(user, socks5_args.users[i].username) == 0 &&
            strcmp(pass, socks5_args.users[i].password) == 0)
            return true;
    }
    return false;
}

bool server_is_full() { return socks5_args.nusers == MAX_USERS; }

void add_user(char *user, char *pass) {
    bool found_available_space = false;
    for (int i = 0; i < MAX_USERS && found_available_space == false; i++) {
        if (socks5_args.users[i].username == NULL ||
            socks5_args.users[i].username[0] == '\0') {
            char *usern = socks5_args.users[i].username;
            strcpy(usern, user);
            char *passw = socks5_args.users[i].password;
            strcpy(passw, pass);
            socks5_args.nusers++;
            found_available_space = true;
        }
    }
}

void delete_user(char *user) {
    bool not_found = true;
    for (int i = 0; i < MAX_USERS && not_found; i++) {
        if (socks5_args.users[i].username != NULL &&
            strcmp(user, socks5_args.users[i].username) == 0) {
            socks5_args.nusers--;
            socks5_args.users[i].password[0] = 0;
            socks5_args.users[i].username[0] = 0;
            not_found = false;
        }
    }
}
