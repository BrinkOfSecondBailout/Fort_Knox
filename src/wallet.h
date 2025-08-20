/* wallet.h */
#include "common.h"

#ifndef WALLET_H
#define WALLET_H

#define N_VALUE_HEX "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define PASSP_MAX 22

#define SEED_LENGTH 64
#define PRIVKEY_LENGTH 32
#define CHAINCODE_LENGTH 32
#define PUBKEY_LENGTH 33
#define CHECKSUM 4

typedef struct key_pair key_pair_t;

struct key_pair {
	uint8_t chain_code[CHAINCODE_LENGTH];
	uint8_t key_priv[PRIVKEY_LENGTH];
	uint8_t key_priv_extended[PRIVKEY_LENGTH + CHAINCODE_LENGTH];
	uint8_t key_pub_compressed[PUBKEY_LENGTH];
	uint8_t key_pub_extended[PUBKEY_LENGTH + CHAINCODE_LENGTH];
	uint8_t key_index;
};

typedef struct {
	char *data;
	size_t size;
} curl_buffer_t;

void resize_convert_hex_to_bytes(const char *, uint8_t *);
void print_bytes_as_hex(const char *, const uint8_t *, size_t);
void print_seed_hashed(const uint8_t *, size_t);
void print_master_priv_key_hashed(const uint8_t *, size_t);
int generate_master_key(const uint8_t *seed, size_t, key_pair_t *);
int derive_child_key(const key_pair_t *, uint32_t, key_pair_t *);
long long get_account_balance(key_pair_t *, uint32_t, int);

#endif
