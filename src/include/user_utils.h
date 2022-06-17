#ifndef USER_UTILS_H_
#define USER_UTILS_H_

#include <stdbool.h>
#define CRED_SIZE 256
typedef struct user_info {
    char username[CRED_SIZE];
    char password[CRED_SIZE];
} user_info;

#define MAX_USERS 10

#define USER_PASS_DELIMETER ':'

bool user_registerd(char * user);

bool check_credentials(char * user, char * pass);

bool server_is_full();

void add_user(char * user, char * pass);

void delete_user(char * user);

#endif 