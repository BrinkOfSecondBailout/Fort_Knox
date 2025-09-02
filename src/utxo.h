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
	key_pair_t *key; // Corresponding private key for signing
} utxo_t;

int estimated_transaction_size(int, int);
int get_fee_rate(long long *, long long *, time_t *);
long long get_utxos(key_pair_t *, utxo_t**, int *, uint32_t, time_t *);
int select_coins(utxo_t *, int, long long, long long, utxo_t **, int *, long long *);
int address_to_scriptpubkey(const char *, uint8_t *, size_t *);
int build_transaction(const char*, long long, utxo_t **, int, key_pair_t *, long long, char *);
int construct_preimage(char *);
int sign_transaction(char *, utxo_t *, int);
int broadcast_transaction(const char *raw_tx_hex, time_t *);

#endif
