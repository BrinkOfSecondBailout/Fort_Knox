/* test_vectors.h */

#ifndef TEST_VECTORS_H
#define TEST_VECTORS_H

typedef struct {
	const char *seed_hex;
	const char *master_priv_hex;
	const char *master_chain_hex;
	const char *paths[5];
	const char *child_priv_hex[5];
	const char *child_chain_hex[5];
} bip32_test_vector_t;

#endif
