/* query.h */

#ifndef QUERY_H
#define QUERY_H

#include <curl/curl.h>
#include "common.h"

typedef struct {
	char *data;
	size_t size;
} curl_buffer_t;

size_t curl_write_callback_func(void *, size_t, size_t, void *);
double get_bitcoin_price(time_t *);
int init_curl_and_addresses(const char **, int, curl_buffer_t *, time_t *);
int estimated_transaction_size(int, int);
int get_fee_rate(long long *, long long *, time_t *);

#endif
