#include <string.h>
#include "user_utils.h"
#include "args.h"

extern struct socks5_args socks5_args;

bool user_registerd(char * user, char * pass) {
    for(int i = 0; i < socks5_args.nusers; i++ ) {
        if(socks5_args.users[i].username != NULL && strcmp(user, socks5_args.users[i].username) == 0 && strcmp(pass, socks5_args.users[i].password) == 0)
            return true;
    }
    return false;
}

bool server_is_full() {
    return socks5_args.nusers == MAX_USERS;
}

void add_user(char * user, char * pass) {
    bool found_available_space = false;
    for(int i = 0; i < socks5_args.nusers && found_available_space == false; i++) {
        if(socks5_args.users[i].username == NULL) {
            socks5_args.users[i].username = user;
            socks5_args.users[i].password = pass;
            socks5_args.nusers++;
            found_available_space = true;
        }
    }
    if(found_available_space == false) {
        socks5_args.users[socks5_args.nusers].username = user;
        socks5_args.users[socks5_args.nusers++].password = pass;
    }
}

void delete_user(char * user, char * pass) {
    for(int i = 0; i < socks5_args.nusers; i++ ) {
        if(socks5_args.users[i].username != NULL && strcmp(user, socks5_args.users[i].username) == 0 && strcmp(pass, socks5_args.users[i].password) == 0) {
            socks5_args.users[i].username = NULL;
            socks5_args.users[i].password = NULL;
            socks5_args.nusers--;
        }  
    }
}
