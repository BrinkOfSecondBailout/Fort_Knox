/* knox.h */

#ifndef KNOX_H
#define KNOX_H
#include "wallet.h"


typedef unsigned int int32;

typedef struct {
	uint8_t seed[SEED_LENGTH];
	key_pair_t *master_key;
	account_t **accounts;
	size_t accounts_count;
	size_t accounts_capacity;
	time_t last_api_request;
} User;

typedef int32 (*Callback)(User *user);

typedef struct {
	char *command_name;
	Callback callback_function;
} Command_Handler;

int32 new_handle(User *user);
int32 recover_handle(User *user);
int32 balance_handle(User *user);
int32 receive_handle(User *user);
int32 send_handle(User *user);
int32 help_handle(User *user);
int32 menu_handle(User *user);
int32 exit_handle(User *user);
#endif
