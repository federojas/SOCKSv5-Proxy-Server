#ifndef USER_UTILS_H_
#define USER_UTILS_H_

#include <stdbool.h>

#define MAX_USERS 10

#define USER_PASS_DELIMETER ':'

bool user_registerd(char * user, char * pass);

bool server_is_full();

void add_user(char * user, char * pass);

void delete_user(char * user, char * pass);

#endif 