/* memory.c */

#include "memory.h"
#include "crypt.h"
#include "hash.h"


void zero(void *buf, size_t size) {
	if (!buf) return;
	memset(buf, 0, size);
	return;
}

void zero_multiple(void *buf, ...) {
	va_list args;
	va_start(args, buf);
	void *ptr;
	while ((ptr = va_arg(args, void *)) != NULL) {
		zero(ptr, sizeof(*ptr));
	}
	va_end(args);
}

void zero_and_gcry_free(void *buf, size_t size) {
	if (!buf) return;
	zero(buf, size);
	gcry_free(buf);
}

void zero_and_gcry_free_multiple(size_t size, void *buf, ...) {
	va_list args;
	va_start(args, buf);
	void *ptr;
	while ((ptr = va_arg(args, void *)) != NULL) {
		zero(ptr, sizeof(*ptr));
		gcry_free(buf);
	}
	va_end(args);
}

void free_rbf_outputs_array(rbf_output_t **outputs, size_t j) {
	for (size_t i = 0; i < j; i++) {
		if (outputs[i] != NULL) gcry_free((void *)outputs[i]);
	}
	gcry_free((void *)outputs);
}

void free_utxos_array(utxo_t **utxos, int *num_utxos, size_t j) {
	for (size_t i = 0; i < j; i++) {
		if (utxos[i]->key != NULL) gcry_free((void *)utxos[i]->key);
		if (utxos[i] != NULL) gcry_free((void *)utxos[i]);
	}
	gcry_free((void *)utxos);
	*num_utxos = 0;
}

void free_complete_rbf(rbf_data_t *rbf_data) {
	free(rbf_data->raw_tx_hex);
	free_utxos_array(rbf_data->utxos, &(rbf_data->num_inputs), (size_t)rbf_data->num_inputs);
	free_rbf_outputs_array(rbf_data->outputs, (size_t)rbf_data->num_outputs);
	zero_and_gcry_free((void *)rbf_data, sizeof(rbf_data_t));	
}

void free_addresses_and_keys(char **addresses, key_pair_t **child_keys, int num_addresses_and_keys) {
	for (size_t i = 0; i < num_addresses_and_keys; i++) {
		free(addresses[i]);
		if (child_keys[i] != NULL) gcry_free((void *)child_keys[i]);
	}
	free(addresses);
	gcry_free((void *)child_keys);
}

void free_addresses(char **addresses, size_t i) {
	for (size_t j = 0; j < i; j++) free(addresses[j]);
	free(addresses);
}

