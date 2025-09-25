/* wallet.h */
#include "common.h"

#ifndef WALLET_H
#define WALLET_H

#define SATS_PER_BTC 100000000.0
#define CURVE_ORDER "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define HARD_FLAG 0x80000000
#define SECS_PER_REQUEST 15

#define INITIAL_USED_INDEXES_CAPACITY 20
#define SEED_LENGTH 64
#define PRIVKEY_LENGTH 32
#define CHAINCODE_LENGTH 32
#define PUBKEY_LENGTH 33
#define CHECKSUM 4
#define GAP_LIMIT 20
#define ADDRESS_MAX_LEN 100
#define BECH32_VALUES_MAX 100


typedef struct {
	uint8_t chain_code[CHAINCODE_LENGTH];
	uint8_t key_priv[PRIVKEY_LENGTH];
	uint8_t key_priv_extended[PRIVKEY_LENGTH + CHAINCODE_LENGTH];
	uint8_t key_pub_compressed[PUBKEY_LENGTH];
	uint8_t key_pub_extended[PUBKEY_LENGTH + CHAINCODE_LENGTH];
	uint32_t key_index;
	uint8_t depth; // how many derivations deep from master key
} key_pair_t ;

int serialize_extended_key(key_pair_t *, key_pair_t *, int, char **);
int key_to_pubkeyhash(key_pair_t *key, uint8_t *pubkeyhash);
int pubkeyhash_to_address(const uint8_t *, size_t, char *, size_t);
int pubkey_to_address(const uint8_t *, size_t, char *, size_t);
int generate_master_key(const uint8_t *seed, size_t, key_pair_t *);
int derive_child_key(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_change_to_child(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_account_to_change(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_master_to_account(const key_pair_t *, uint32_t, key_pair_t *);
int derive_from_master_to_coin(const key_pair_t *, key_pair_t *);
int derive_from_master_to_child(const key_pair_t *, uint32_t, uint32_t, uint32_t, key_pair_t *);
int generate_receive_address(const key_pair_t *, char *, uint32_t, uint32_t);
#endif
