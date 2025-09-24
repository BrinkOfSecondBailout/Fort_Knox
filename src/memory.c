/* memory.c */

#include "memory.h"
#include "crypt.h"
#include "hash.h"

mempool_t *mempool;

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

void free_all() {	
	object_t *temp = NULL;
	object_t *curr = mempool->head;
	while (curr) {
		temp = curr->next;
		zero_and_gcry_free(curr->object, sizeof(curr->object));
		mempool->total_bytes -= sizeof(curr->object);
		curr = temp;
	}
	printf("All objects in mempool freed.\n");
	printf("Mempool total bytes: %ld\n", mempool->total_bytes);
	return;
}

void remove_from_mempool(void *object, size_t size) {
	object_t *previous = NULL;
	object_t *curr = NULL;
	curr = mempool->head;
	while (curr) {
		if (curr->object == object) {
			if (previous) {
				previous->next = curr->next;
			}
			zero_and_gcry_free(object, size);
			mempool->total_bytes -= size;
			return;
		}
		previous = curr;
		curr = curr->next;
	}
	fprintf(stderr, "Cannot find object to free in mempool\n");
	exit(1);
}

void add_to_mempool(void *object, size_t size) {
	if (mempool->total_bytes + size >= mempool->total_capacity) {
		fprintf(stderr, "Memory exceeded. Shutting down.\n");
		free_all();
		exit(1);
	}
	if (mempool->head) {
		object_t *curr = mempool->head;
		while (curr->next != NULL) {
			curr = curr->next;
		}
		curr->next->object = object;
	} else {
		mempool->head->object = object;
	}
	mempool->total_bytes += size;
	return;
}

void *g_malloc(size_t size) {
	void *result = gcry_malloc_secure(size);
	if (!result) {
		fprintf(stderr, "Unable to allocate object in mempool.\n");
		free_all();
		exit(1);
	}
	add_to_mempool(result, size);
	return result;
}

void *g_calloc(size_t size) {
	void *result = gcry_calloc_secure(1, size);
	if (!result) {
		fprintf(stderr, "Unable to allocate object in mempool.\n");
		free_all();
		exit(1);
	}
	add_to_mempool(result, size);
	return result;
}

void g_free(void *object) {
	remove_from_mempool(object, sizeof(object));
	return;
}

void free_rbf_outputs_array(rbf_output_t **outputs, size_t j) {
	for (size_t i = 0; i < j; i++) {
		if (outputs[i] != NULL) g_free((void *)outputs[i]);
	}
	g_free((void *)outputs);
}

void free_utxos_array(utxo_t **utxos, int *num_utxos, size_t j) {
	for (size_t i = 0; i < j; i++) {
		if (utxos[i]->key != NULL) g_free((void *)utxos[i]->key);
		if (utxos[i] != NULL) g_free((void *)utxos[i]);
	}
	g_free((void *)utxos);
	*num_utxos = 0;
}

void free_complete_rbf(rbf_data_t *rbf_data) {
	g_free((void *)rbf_data->raw_tx_hex);
	free_utxos_array(rbf_data->utxos, &(rbf_data->num_inputs), (size_t)rbf_data->num_inputs);
	free_rbf_outputs_array(rbf_data->outputs, (size_t)rbf_data->num_outputs);
	g_free((void *)rbf_data);	
}

void free_addresses_and_keys(char **addresses, key_pair_t **child_keys, int num_addresses_and_keys) {
	for (size_t i = 0; i < num_addresses_and_keys; i++) {
		g_free((void *)addresses[i]);
		if (child_keys[i] != NULL) g_free((void *)child_keys[i]);
	}
	g_free((void *)addresses);
	g_free((void *)child_keys);
}

void free_addresses(char **addresses, size_t i) {
	for (size_t j = 0; j < i; j++) g_free((void *)addresses[j]);
	g_free((void *)addresses);
}

gcry_error_t init_gcrypt() {
	gcry_error_t err = GPG_ERR_NO_ERROR;
	const char *version =  gcry_check_version(NEED_LIBGCRYPT_VERSION);
	if (!version) {
                fprintf(stderr, "libgcrypt is too old (need %s, have %s)\n",
                        NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
                exit(EXIT_FAILURE);
        }
	err = gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	if (err) {
		fprintf(stderr, "Warning suspension failed\n");
                exit(EXIT_FAILURE);
	}
        err = gcry_control(GCRYCTL_INIT_SECMEM, MEMPOOL_CAPACITY, 0);
        if (err) {
		fprintf(stderr, "Secure memory enabling failed\n");
                exit(EXIT_FAILURE);
	}
	err = gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	if (err) {
		fprintf(stderr, "Enabling memory warnings failed\n");
                exit(EXIT_FAILURE);
	}
	err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	if (err) {
		fprintf(stderr, "Gcrypt initialization completion failed\n");
                exit(EXIT_FAILURE);
	}
	mempool->head = NULL;
	mempool->total_bytes = 0;
	mempool->total_capacity = MEMPOOL_CAPACITY;
	
	err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P);
	return err;
}

