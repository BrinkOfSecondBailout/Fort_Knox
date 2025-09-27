/* memory.c */

#include "memory.h"
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

void remove_from_mempool(void *object, size_t size) {
	object_t *prev = NULL;
	object_t *curr = mempool->head;
	while (curr != NULL) {
		if (curr->object == object) {
			zero_and_gcry_free(object, size);
			curr->object = NULL;
			if (prev == NULL) {
				mempool->head = curr->next;
			} else {
				prev->next = curr->next;
			}
			gcry_free(curr);
			mempool->total_bytes -= (size + sizeof(object_t));
			return;
		}
		prev = curr;
		curr = curr->next;
	}
	fprintf(stderr, "Cannot find object %p in mempool\n", object);
	return;
}

void add_to_mempool(void *object, size_t size) {
	if (mempool->total_bytes + size + sizeof(object_t) >= mempool->total_capacity) {
		fprintf(stderr, "Memory exceeded. Shutting down.\n");
		free_all();
		exit(1);
	}	
	object_t *node = (object_t *)gcry_malloc_secure(sizeof(object_t ));
	mempool->total_bytes += sizeof(object_t);
	if (!node) {
		fprintf(stderr, "Failure allocating object.\n");
		free_all();
		exit(1);
	}
	node->object = object;
	mempool->total_bytes += size;
	node->next = mempool->head;
	mempool->head = node;
	return;
}

void *g_malloc(size_t size) {
	void *result = gcry_malloc_secure(size);
	if (!result) {
		fprintf(stderr, "Failure allocating item.\n");
		free_all();
		exit(1);
	}
	add_to_mempool(result, size);
	return result;
}

void *g_calloc(size_t size) {
	void *result = gcry_calloc_secure(1, size);
	if (!result) {
		fprintf(stderr, "Failure allocating item.\n");
		free_all();
		exit(1);
	}
	add_to_mempool(result, size);
	return result;
}

void g_free(void *object, size_t size) {
	remove_from_mempool(object, size);
	return;
}

void g_free_multiple(size_t size, void *object, ...) {
	va_list args;
	va_start(args, object);
	void *ptr;
	while ((ptr = va_arg(args, void *)) != NULL) {
		g_free(ptr, size);
	}
	va_end(args);
}


void init_mempool() {
	mempool->head = NULL;
	mempool->total_bytes = 0;
	mempool->total_capacity = MEMPOOL_CAPACITY;
}

void free_all() {	
	printf("Freeing all remaining objects in mempool.\n");
	object_t *temp = NULL;
	object_t *curr = mempool->head;
	while (curr) {
		temp = curr->next;
		mempool->total_bytes -= (sizeof(curr->object) + sizeof(object_t));
		gcry_free((void *)curr->object);
		gcry_free((void *)curr);
		curr = temp;
	}
	printf("All objects in mempool freed.\n");
	printf("Mempool total bytes: %ld\n", mempool->total_bytes);
	init_mempool();	
	zero_and_gcry_free(mempool, sizeof(mempool_t));
	return;
}


void free_rbf_outputs_array(rbf_output_t **outputs, size_t j) {
	for (size_t i = 0; i < j; i++) {
		if (outputs[i] != NULL) g_free((void *)outputs[i], sizeof(rbf_output_t));
	}
	g_free((void *)outputs, j * sizeof(rbf_output_t **));
}

void free_utxos_array(utxo_t **utxos, int *num_utxos, size_t j) {
	for (size_t i = 0; i < j; i++) {
		if (utxos[i]->key != NULL) g_free((void *)utxos[i]->key, sizeof(key_pair_t));
		if (utxos[i] != NULL) g_free((void *)utxos[i], sizeof(utxo_t));
	}
	g_free((void *)utxos, *num_utxos * sizeof(utxo_t **));
	*num_utxos = 0;
}

void free_complete_rbf(rbf_data_t *rbf_data) {
	g_free(rbf_data->raw_tx_hex, MAX_RAW_TX_HEX);
	free_utxos_array(rbf_data->utxos, &(rbf_data->num_inputs), (size_t)rbf_data->num_inputs);
	free_rbf_outputs_array(rbf_data->outputs, (size_t)rbf_data->num_outputs);
	g_free((void *)rbf_data, sizeof(rbf_data_t *));
}

void free_addresses_and_keys(char **addresses, key_pair_t **child_keys, int num_addresses_and_keys) {
	for (size_t i = 0; i < num_addresses_and_keys; i++) {
		g_free((void *)addresses[i], ADDRESS_MAX_LEN);
		if (child_keys[i] != NULL) g_free((void *)child_keys[i], sizeof(key_pair_t));
	}
	g_free((void *)addresses, num_addresses_and_keys * sizeof(char *));
	g_free((void *)child_keys, num_addresses_and_keys * sizeof(key_pair_t *));
}

void free_addresses(char **addresses, size_t i, size_t num_addresses) {
	for (size_t j = 0; j < i; j++) g_free((void *)addresses[j], ADDRESS_MAX_LEN);
	g_free((void *)addresses, num_addresses * sizeof(char *));
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
	mempool = gcry_malloc_secure(sizeof(mempool_t));
	if (!mempool) {
		fprintf(stderr, "Failure allocating main mempool. Exiting.\n");
		exit(1);
	}
	init_mempool();	

	err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P);
	return err;
}

