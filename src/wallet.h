/* wallet.h */
#include "common.h"

#ifndef WALLET_H
#define WALLET_H

#define SATS_PER_BTC 100000000.0
#define N_VALUE_HEX "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define HARD_FLAG 0x80000000
#define SECS_PER_REQUEST 30

#define ACCOUNTS_CAPACITY 5
#define INITIAL_USED_INDEXES_CAPACITY 20
#define SEED_LENGTH 64
#define PRIVKEY_LENGTH 32
#define CHAINCODE_LENGTH 32
#define PUBKEY_LENGTH 33
#define CHECKSUM 4
#define GAP_LIMIT 20
#define ADDRESS_MAX_LEN 100
#define BECH32_VALUES_MAX 100
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
	uint32_t account_index;
	uint32_t used_indexes_count;
} account_t;

typedef struct {
	char *data;
	size_t size;
} curl_buffer_t;

void zero(void *, size_t);
void zero_multiple(void *, ...);
void zero_and_gcry_free(void *, size_t);
void zero_and_gcry_free_multiple(size_t, void *, ...);
void hex_to_bytes(const char *, uint8_t *, size_t);
void resize_convert_hex_to_bytes(const char *, uint8_t *);
void print_bytes_as_hex(const char *, const uint8_t *, size_t);
void print_seed_hashed(const uint8_t *, size_t);
void print_master_priv_key_hashed(const uint8_t *, size_t);
int pubkey_to_address(const uint8_t *, size_t, char *, size_t);
int generate_master_key(const uint8_t *seed, size_t, key_pair_t *);
int derive_child_key(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_change_to_child(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_account_to_change(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_public_to_account(const key_pair_t *, uint32_t, key_pair_t *);
size_t curl_write_callback_func(void *, size_t, size_t, void *);
double get_bitcoin_price(time_t*);
long long get_account_balance(key_pair_t *, uint32_t, time_t*);

#endif
