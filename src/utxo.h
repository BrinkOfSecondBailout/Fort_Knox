/* utxo.h */

#ifndef UTXO_H
#define UTXO_H

#include "common.h"
#include "wallet.h"

#define TX_VERSION 2 // Segwit
#define SIGHASH_ALL 0x01

typedef struct {
	char txid[65]; // 64 hex + null
	uint32_t vout; // Output index of input in the transaction
	long long amount;
	char address[ADDRESS_MAX_LEN];
	key_pair_t *key; // Corresponding key for signing
} utxo_t;

typedef struct {
	char txid[65];
	int unconfirmed; // 1 if unconfirmed
	int num_inputs;
	int num_outputs;
	long long fee;
	char *raw_tx_hex;
} rbf_data_t;

int estimated_transaction_size(int, int);
int get_fee_rate(long long *, long long *, time_t *);
long long get_utxos(key_pair_t *, utxo_t**, int *, uint32_t, time_t *);
int select_coins(utxo_t *, int, long long, long long, utxo_t **, int *, long long *);
int address_to_scriptpubkey(const char *, uint8_t *, size_t *);
int calculate_rbf_fee(rbf_data_t *, double, time_t *, long long *, long long *);
int build_rbf_transaction(rbf_data_t *, long long, long long);
int build_transaction(const char*, long long, utxo_t **, int, key_pair_t *, long long, char **, uint8_t **, size_t *, int);
int construct_preimage(uint8_t *, size_t, utxo_t **, int, uint8_t *);
int sign_transaction(char **, utxo_t **, int);
int broadcast_transaction(char **, time_t *);

#endif
