/* query.h */

#ifndef QUERY_H
#define QUERY_H

#include <curl/curl.h>
#include "common.h"
#include "utxo.h"

typedef struct {
	char *data;
	size_t size;
} curl_buffer_t;

size_t curl_write_callback_func(void *, size_t, size_t, void *);
double get_bitcoin_price(time_t *);
int init_curl_and_addresses(const char **, int, curl_buffer_t *, time_t *);
int estimate_transaction_size(int, int);
int get_fee_rate(long long *, long long *, time_t *);
size_t curl_write_callback_func(void *, size_t, size_t, void *);
double get_bitcoin_price(time_t*);
int fetch_raw_tx_hex(char *, rbf_data_t *, time_t *);
int check_rbf_transaction(char *, rbf_data_t*, time_t*);
long long get_account_balance(key_pair_t *, uint32_t, time_t*);
int scan_one_accounts_external_chain(key_pair_t *, uint32_t, time_t *);

#endif
