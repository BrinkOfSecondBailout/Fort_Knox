/* knox.h */

#ifndef KNOX_H
#define KNOX_H
#include "wallet.h"

typedef unsigned int int32;

typedef struct {
        uint32_t account_index;
        uint32_t used_indexes_count;
} account_t;

typedef struct {
	uint8_t seed[SEED_LENGTH]; // 64 bytes
	key_pair_t *master_key;
	int has_master_key;
	account_t **accounts;
	size_t accounts_count;
	size_t accounts_capacity;
	time_t last_api_request;
	double last_price_cached;
} User;

typedef int32 (*Callback)(User *user);

typedef struct {
	char *command_name;
	Callback callback_function;
} Command_Handler;

int32 price_handle(User *);
int32 new_handle(User *);
int32 recover_handle(User *);
int32 key_handle(User *);
int32 balance_handle(User *);
int32 fee_handle(User *);
int32 receive_handle(User *);
int32 send_handle(User *);
int32 rbf_handle(User *);
int32 help_handle(User *);
int32 menu_handle(User *);
int32 exit_handle(User *);
void increment_account_used_index(account_t *);
#endif
