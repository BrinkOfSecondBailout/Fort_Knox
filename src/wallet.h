/* wallet.h */
#include "common.h"

#ifndef WALLET_H
#define WALLET_H

#define PASSP_MAX 22

#define PRIVKEY_LENGTH 32
#define CHAINCODE_LENGTH 32
#define PUBKEY_LENGTH 33
#define CHECKSUM 4

typedef struct {
	uint8_t chain_code[CHAINCODE_LENGTH];
	uint8_t key_priv[PRIVKEY_LENGTH];
	uint8_t key_priv_extended[PRIVKEY_LENGTH + CHAINCODE_LENGTH];
	uint8_t key_pub_compressed[PUBKEY_LENGTH];
	uint8_t key_pub_extended[PUBKEY_LENGTH + CHAINCODE_LENGTH];
	uint8_t key_index;
} key_pair_t;

typedef struct {
	char *data;
	size_t size;
} curl_buffer_t;

int generate_master_key(const key_pair_t *, key_pair_t *);
int derive_child_key(const key_pair_t *, uint32_t, key_pair_t *);
long long get_account_balance(key_pair_t *, uint32_t, int);

#endif
