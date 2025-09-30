/* utxo.h */

#ifndef UTXO_H
#define UTXO_H

#include "common.h"
#include "wallet.h"

#define TX_VERSION 2 // Segwit
#define SIGHASH_ALL 0x01
#define MAX_RAW_TX_HEX 1000
typedef struct {
	char txid[65]; // 64 hex + null
	uint32_t vout; // Output index of input in the transaction
	long long amount;
	char address[ADDRESS_MAX_LEN];
	key_pair_t *key; // Corresponding key for signing
} utxo_t;

typedef struct {
	char address[ADDRESS_MAX_LEN];
	long long amount;
} rbf_output_t;

typedef struct {
	char txid[65];
	uint32_t account_index;
	int unconfirmed; // 1 if unconfirmed
	int num_inputs;
	utxo_t **utxos;
	int num_outputs;
	rbf_output_t **outputs;
	long long old_fee;
	long long new_fee;
	char *raw_tx_hex;
} rbf_data_t;

int estimated_transaction_size(int, int);
int get_fee_rate(long long *, long long *, time_t *);
long long get_utxos_key_and_balance(key_pair_t *, utxo_t***, int *, uint32_t, time_t *);
int select_coins(utxo_t **, int, long long, long long, utxo_t ***, int *, long long *);
int address_to_scriptpubkey(const char *, uint8_t *, size_t *);
int check_rbf_sequence(char *, int);
int calculate_rbf_fee(rbf_data_t *, double, time_t *);
int match_utxos_to_keys(key_pair_t *, rbf_data_t *);
int build_rbf_transaction(rbf_data_t *, char **, uint8_t **, size_t *);
int build_transaction(const char*, long long, utxo_t **, int, key_pair_t *, long long, char **, uint8_t **, size_t *, int);
int construct_preimage(uint8_t *, size_t, utxo_t **, int, uint8_t *);
int sign_transaction(char **, utxo_t **, int);
int broadcast_transaction(char *, time_t *);

#endif
