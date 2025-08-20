/* knox.h */

#ifndef KNOX_H
#define KNOX_H
#include "wallet.h"

typedef unsigned int int32;

typedef int32 (*Callback)();

typedef struct {
	char *command_name;
	Callback callback_function;
} Command_Handler;

typedef struct {
	uint8_t seed[SEED_LENGTH];
	key_pair_t *master_key;
	key_pair_t **child_keys;
	size_t child_key_count;
	size_t child_key_capacity;
} User;

int32 new_handle();
int32 recover_handle();
int32 balance_handle();
int32 receive_handle();
int32 send_handle();
int32 help_handle();
int32 menu_handle();
int32 exit_handle();
#endif
