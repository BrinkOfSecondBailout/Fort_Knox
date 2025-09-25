/* memory.h */
#ifndef MEMORY_H
#define MEMORY_H

#include "common.h"
#include "utxo.h"
#include "wallet.h"
#include "gcrypt.h"

#define NEED_LIBGCRYPT_VERSION "1.10.1"

#define MEMPOOL_CAPACITY 262144 // 256 kb

typedef struct object_t {
	void *object;
	struct object_t *next;
} object_t;

typedef struct {
	object_t *head;
	size_t total_bytes;
	size_t total_capacity;
} mempool_t;

void zero(void *, size_t);
void zero_multiple(void *, ...);
void zero_and_gcry_free(void *, size_t );
void zero_and_gcry_free_multiple(size_t, void *, ...);
void free_all();
void *g_malloc(size_t);
void *g_calloc(size_t);
void g_free(void *, size_t);
void g_free_multiple(size_t , void *, ...);
void free_rbf_outputs_array(rbf_output_t **, size_t);
void free_utxos_array(utxo_t **, int *, size_t);
void free_complete_rbf(rbf_data_t *);
void free_addresses_and_keys(char **, key_pair_t **, int);
void free_addresses(char **, size_t, size_t);
gcry_error_t init_gcrypt();

#endif
