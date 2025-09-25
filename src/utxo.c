/* utxo.c */
#include <curl/curl.h>
#include <jansson.h>
#include "utxo.h"
#include "hash.h"
#include "query.h"
#include "memory.h"

long long query_utxos(char **addresses, int num_addresses_and_keys, utxo_t ***utxos, int *num_utxos, key_pair_t **child_keys, time_t *last_request) {
	printf("Querying UTXOs...\n");
	long long total_balance = 0;
	if (*addresses[0] == '\0' || num_addresses_and_keys == 0) {
		fprintf(stderr, "Addresses invalid.\n");
		return -1;
	}
	// Set a curl handle for the data transfer
	CURL *curl = curl_easy_init();
	if (!curl) return -1;
	// Build pipe-separated address list for API
	char addr_list[1024 * 2] = {0};

	for (size_t i = 0; i < num_addresses_and_keys; i++) {
		strncat(addr_list, addresses[i], sizeof(addr_list) - strlen(addr_list) - 2);
		if (i < num_addresses_and_keys - 1) strncat(addr_list, "|", sizeof(addr_list) - strlen(addr_list) - 2);
	}
	char url[2048];
	snprintf(url, sizeof(url), "https://blockchain.info/unspent?active=%s", addr_list);
	
	// Set the behaviors for the curl handle
	curl_buffer_t buffer = {0};
	curl_easy_setopt(curl, CURLOPT_URL, url);
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
    	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

	time_t now = time(NULL);
	if (*last_request != 0 && difftime(now, *last_request) < SECS_PER_REQUEST) {
		int sleep_time = SECS_PER_REQUEST - (int)difftime(now, *last_request);
		printf("Rate limit: 1 request per %d seconds...\nWaiting %d seconds...\n", SECS_PER_REQUEST, sleep_time);
		sleep(sleep_time);
	}
    	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
    	curl_easy_cleanup(curl);
    	if (res != CURLE_OK) {
		fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
		free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
		free(buffer.data);
		return -1;
    	}
	// Parse JSON for total balance
	json_error_t error;
	json_t *root = json_loads(buffer.data, 0, &error);
	free(buffer.data);
	json_t *unspent_outputs = json_object_get(root, "unspent_outputs");
	if (!root || !json_is_array(unspent_outputs)) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
		return -1;
	}
	// Allocate UTXOs
	*num_utxos = json_array_size(unspent_outputs);
	*utxos = (utxo_t **)g_malloc(*num_utxos * sizeof(utxo_t*));
	if (*num_utxos == 0 || !*utxos) {
		fprintf(stderr, "Failure allocating utxos\n");
		free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
		json_decref(root);
		return -1;
	}
	for (size_t i = 0; i < *num_utxos; i++) {
		utxo_t *utxo = (utxo_t *)g_calloc(sizeof(utxo_t));
		if (!utxo) {
			fprintf(stderr, "Error allocating utxo\n");
			free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
			free_utxos_array(*utxos, num_utxos, i);
			json_decref(root);
			return -1;
		}
		json_t *output = json_array_get(unspent_outputs, i);
		json_t *tx_hash = json_object_get(output, "tx_hash");
		json_t *tx_output_n = json_object_get(output, "tx_output_n");
		json_t *value = json_object_get(output, "value");
		if (!json_is_string(tx_hash) || !json_is_integer(tx_output_n) || !json_is_integer(value)) {
			fprintf(stderr, "Invalid UTXO data\n");
			free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
			free_utxos_array(*utxos, num_utxos, i);
			json_decref(root);
			return -1;
		}
		// Copy values over to utxo struct
		strncpy(utxo->txid, json_string_value(tx_hash), 64);
		utxo->vout = (uint32_t)json_integer_value(tx_output_n);
		utxo->amount = (long long)json_integer_value(value);
		total_balance += utxo->amount;
		// Convert script to Bech32 address
		json_t *script = json_object_get(output, "script");
		if (!json_string_value(script)) {
			fprintf(stderr, "Invalid UTXO data\n");		
			free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
			free_utxos_array(*utxos, num_utxos, i);
			json_decref(root);
			return -1;
		}
		const char *script_hex = json_string_value(script);
		char utxo_address[ADDRESS_MAX_LEN];
		if (strlen(script_hex) >= 4) {
			// Extract 20-byte pubkeyhash from script (skip 0014)
			uint8_t hash[20];
			hex_to_bytes(script_hex + 4, hash, 20);
			// Turn the pkh to address
			if (pubkeyhash_to_address(hash, 22, utxo_address, ADDRESS_MAX_LEN) != 0) {
				free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
				free_utxos_array(*utxos, num_utxos, i);
				json_decref(root);
				return -1;
			}
		} else {
			fprintf(stderr, "Invalid script for UTXO\n");
			free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
			free_utxos_array(*utxos, num_utxos, i);
			json_decref(root);
			return -1;
		}
		utxo->key = NULL;
		for (size_t j = 0; j < num_addresses_and_keys; j++) {
			if (strncmp(utxo_address, addresses[j], ADDRESS_MAX_LEN) == 0) {
				utxo->key = child_keys[j];
				child_keys[j] = NULL; // Transferring ownership to utxo->key and preventing double-free
				strncpy(utxo->address, utxo_address, ADDRESS_MAX_LEN);
				break;
			}
		}
		if (!utxo->key) {
			fprintf(stderr, "No matching key for UTXO address %s. Skipping.\n", utxo_address);
		}
		(*utxos)[i] = utxo;
	}
	free_addresses_and_keys(addresses, child_keys, num_addresses_and_keys);
	json_decref(root);
	return total_balance;
}

long long get_utxos_balance(key_pair_t *master_key, utxo_t ***utxos, int *num_utxos, uint32_t account_index, time_t *last_request) {
	if (!master_key) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	printf("Gathering UTXO's for account %u...\n", account_index);
	char **addresses = NULL;
	size_t num_allocated = GAP_LIMIT * 2;
	addresses = (char **)g_malloc(num_allocated * sizeof(char *));
	key_pair_t **child_keys = NULL;
	child_keys = (key_pair_t **)g_malloc(num_allocated * sizeof(key_pair_t *));
	if (!addresses || !child_keys) {
		fprintf(stderr, "Failed to allocate addresses or child keys array\n");
		if (addresses) g_free((void *)addresses, num_allocated * sizeof(char *));
		if (child_keys) g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
		return 1;
	}
	int addr_and_key_count = 0;
	for (size_t i = 0; i < num_allocated; i++) {
		// Allocate each of the 40 addresses and NULL it
		char *address = (char *)g_malloc(sizeof(char) * ADDRESS_MAX_LEN);
		if (!address) {
			free_addresses(addresses, i, num_allocated);
			g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
			fprintf(stderr, "Error allocating address\n");
			return 1;
		}
		zero((void *)address, ADDRESS_MAX_LEN);
		addresses[i] = address;
	}
	key_pair_t *account_key = NULL;
	account_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		free_addresses(addresses, num_allocated, num_allocated);
		g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
		return 1;
	}
	if (derive_from_master_to_account(master_key, account_index, account_key) != 0) { 
		fprintf(stderr, "Failure deriving account key\n");
		free_addresses(addresses, num_allocated, num_allocated);
		g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
		g_free((void *)account_key, sizeof(key_pair_t));
		return 1;
	}
	for (uint32_t change = 0; change < 2; change++) { // 0 for external, 1 for internal
		key_pair_t *change_key = NULL;
		change_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
		if (!change_key) {
			fprintf(stderr, "Error gcry_malloc_secure\n");
			free_addresses(addresses, num_allocated, num_allocated);
			g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
			g_free((void *)account_key, sizeof(key_pair_t));
			return 1;
		}
		if (derive_from_account_to_change(account_key, change, change_key) != 0) {
			fprintf(stderr, "Failure deriving child key\n");
			free_addresses(addresses, num_allocated, num_allocated);
			g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
			g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
			return 1;
		}
		// For each change (chain), go through all the indexes
		for (uint32_t child_index = 0; child_index < (uint32_t) GAP_LIMIT; child_index++) {
			key_pair_t *child_key = NULL;
			child_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
			if (!child_key) {
				fprintf(stderr, "Error gcry_malloc_secure\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
				return 1;
			}
			if (derive_from_change_to_child(change_key, child_index, child_key) != 0) {
				fprintf(stderr, "Failed to derive child key\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return 1;
			}
			if (pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, addresses[addr_and_key_count], ADDRESS_MAX_LEN) != 0) {
				fprintf(stderr, "Failed to generate address\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return 1;
			}
			child_keys[addr_and_key_count] = child_key;
			addr_and_key_count++;
		}
		g_free((void *)change_key, sizeof(key_pair_t));
	}
	g_free((void *)account_key, sizeof(key_pair_t));
    	return query_utxos(addresses, addr_and_key_count, utxos, num_utxos, child_keys, last_request);	
}

static int compare_utxos(const void *a, const void *b) {
	const utxo_t *utxo_a = (const utxo_t *)a;
	const utxo_t *utxo_b = (const utxo_t *)b;
	if (utxo_a->amount > utxo_b->amount) return -1;
	if (utxo_a->amount < utxo_b->amount) return 1;
	return 0;
}

int select_coins(utxo_t **utxos, int num_utxos, long long amount, long long fee, utxo_t ***selected, int *num_selected, long long *input_sum) {
	// Greedy
	if (!utxos || num_utxos <= 0 || amount <= 0 || fee <= 0) {
		fprintf(stderr, "Invalid input\n");
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 1;
	}
	printf("Preparing the most optimal UTXO's set for your transaction...\n");
	long long total_available = 0;
	for (int i = 0; i < num_utxos; i++) {
		total_available += utxos[i]->amount;
	}
	if (total_available < amount + fee) {
		fprintf(stderr, "Insufficient funds: %lld available, %lld needed.\n", total_available, amount + fee);
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 1;
	}
	utxo_t **sorted_utxos = (utxo_t **)g_calloc(num_utxos * sizeof(utxo_t *));
	if (!sorted_utxos) {
		fprintf(stderr, "Failed to allocate sorted utxos\n");
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 1;
	}
	int num_sorted = num_utxos;
	memcpy(sorted_utxos, utxos, num_utxos * sizeof(utxo_t*));
	qsort(sorted_utxos, num_utxos, sizeof(utxo_t*), compare_utxos);
	long long target = amount + fee;
	*selected = (utxo_t **)g_calloc(num_sorted * sizeof(utxo_t *));
	if (!selected) {
		fprintf(stderr, "Failed to allocate selected UTXO\n");
		free_utxos_array(sorted_utxos, &num_sorted, (size_t)num_sorted);
		return 1;
	}
	// Greedy (largest first)
	for (int i = num_sorted - 1; i >= 0 && *input_sum < target; i--) {
		(*selected)[*num_selected] = sorted_utxos[i];
		*input_sum += sorted_utxos[i]->amount;
		sorted_utxos[i] = NULL; // Transfer ownership and prevent double free
		(*num_selected)++;
	}
	return 0;
}

int address_to_scriptpubkey(const char *address, uint8_t *script, size_t *script_len) {
	uint8_t program[42];
	size_t program_len;
	if (bech32_decode(address, program, &program_len) != 0) {
		fprintf(stderr, "Failed to decode Bech32 address\n");
		return -1;
	}
	if (program[0] != 0 || program_len != 21) {
		fprintf(stderr, "Only P2WPKH (version 0, 20-byte hash) supported\n");
		return -1;
	}
	// ScriptPubKey: 0x00 (OP_0) + 0x14 (length 20) + 20-byte hash
	script[0] = 0x00;
	script[1] = 0x14;
	memcpy(script + 2, program + 1, 20);
	*script_len = 22;
	return 0;
}

int check_rbf_sequence(char *raw_tx_hex, int num_inputs) {
	size_t data_len = strlen(raw_tx_hex) / 2;
	uint8_t tx_data[data_len];
	resize_convert_hex_to_bytes(raw_tx_hex, tx_data);
	size_t pos = 0;
	// Version
	pos += 4;
	// Marker and flag
	pos += 2;
	// Input count
	pos += 1;
	for (int i = 0; i < num_inputs; i++) {
		char sequence_hex[9];
		uint8_t sequence_data[4];	
		// TxId
		pos += 32;
		// Vout
		pos += 4;
		// ScriptSigSize
		pos += 1;
		// Sequence
		memcpy(sequence_data, &tx_data[pos], 4);
		pos += 4;
		// Reverse bytes (little endian)
		reverse_bytes(sequence_data, 4);
		bytes_to_hex(sequence_data, 4, sequence_hex, 9);
printf("Sequence Hex: %s\n", sequence_hex);
		char *endptr;
		long int sequence_val = strtol(sequence_hex, &endptr, 16);
		if (*endptr == '\0' && sequence_val <= 0xFFFFFFFD) {
			return 0;
		}
	}
	return 1;
}

int calculate_rbf_fee(rbf_data_t *rbf_data, double fee_rate_multiplier, time_t *last_request) {
	if (rbf_data->num_inputs <= 0 || rbf_data->num_outputs <= 0 || rbf_data->old_fee <= 0 || fee_rate_multiplier < 1.0 ) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	// Estimate tx virtual size
	int vsize = estimate_transaction_size(rbf_data->num_inputs, rbf_data->num_outputs);
	if (vsize == 0) {
		fprintf(stderr, "Failed to estimate transaction vsize\n");
		return 1;
	}
	printf("Estimated vsize: %d vbytes\n", vsize);
	// Fetch current feerate
	long long regular_rate, priority_rate;
	if (get_fee_rate(&regular_rate, &priority_rate, last_request) != 0) {
		fprintf(stderr, "Failed to fetch fee rate\n");
		return 1;
	}
	// Calculate new fee
	regular_rate *= fee_rate_multiplier;
	printf("New fee rate: ~%lld sat/vbyte\n", regular_rate);
	long long new_fee = (long long)(vsize * regular_rate);
	if (new_fee <= rbf_data->old_fee) {
		new_fee = rbf_data->old_fee + 1000; // Minimum increment (e.g 1000 sats)
		regular_rate = (long long)(new_fee) / vsize;
		printf("Adjusted new fee to exceed original: %lld sat (%lld sat/vbyte)\n", new_fee, regular_rate);
	}
	rbf_data->new_fee = new_fee;
	return 0;	
}

int match_utxos_to_keys(key_pair_t *master_key, rbf_data_t *rbf_data) {
	if (!master_key || !rbf_data || rbf_data->num_inputs <= 0 || !rbf_data->utxos || rbf_data->num_outputs <= 0 ) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	int num_inputs = rbf_data->num_inputs;
	char **addresses = NULL;
	int num_allocated = GAP_LIMIT * 2;
	addresses = (char **)g_malloc(num_allocated * (sizeof(char *)));
	key_pair_t **child_keys = NULL;
	child_keys = (key_pair_t **)g_malloc(num_allocated * sizeof(key_pair_t *));
	if (!addresses || !child_keys) {
		fprintf(stderr, "Failed to allocate addresses or child keys array\n");
		if (addresses) g_free((void *)addresses, num_allocated * sizeof(char *));
		if (child_keys) g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
		return 1;
	}
	int addr_and_key_count = 0;	
	for (size_t i = 0; i < num_allocated; i++) {
		// Allocate each of the 40 addresses and NULL it
		char *address = (char *)g_malloc(ADDRESS_MAX_LEN);
		if (!address) {
			fprintf(stderr, "Error allocating address\n");
			free_addresses(addresses, i, num_allocated);
			g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
			return 1;
		}
		zero((void *)address, ADDRESS_MAX_LEN);
		addresses[i] = address;
	}
	key_pair_t *account_key = NULL;
	account_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		free_addresses(addresses, num_allocated, num_allocated);
		g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
		return 1;
	}
	if (derive_from_master_to_account(master_key, (uint32_t)rbf_data->account_index, account_key) != 0) {
		fprintf(stderr, "Failure deriving account key\n");
		free_addresses(addresses, num_allocated, num_allocated);
		g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
		g_free((void *)account_key, sizeof(key_pair_t));
		return 1;
	}
	for (uint32_t change = 0; change < 2; change++) { // 0 for external, 1 for internal
		key_pair_t *change_key = NULL;
		change_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
		if (!change_key) {
			fprintf(stderr, "Error gcry_malloc_secure\n");
			free_addresses(addresses, num_allocated, num_allocated);
			g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
			g_free((void *)account_key, sizeof(key_pair_t));
			return 1;
		}
		if (derive_from_account_to_change(account_key, change, change_key) != 0) {
			fprintf(stderr, "Failure deriving child key\n");
			free_addresses(addresses, num_allocated, num_allocated);
			g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
			g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
			return 1;
		}
		// For each change (chain), go through all the indexes
		for (uint32_t child_index = 0; child_index < (uint32_t)GAP_LIMIT; child_index++) {
			key_pair_t *child_key = NULL;
			child_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
			if (!child_key) {
				fprintf(stderr, "Error gcry_malloc_secure\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
				return 1;
			}
			if (derive_from_change_to_child(change_key, child_index, child_key) != 0) {
				fprintf(stderr, "Failed to derive child key\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return 1;
			}
			if (pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, addresses[addr_and_key_count], ADDRESS_MAX_LEN) != 0) {
				fprintf(stderr, "Failed to generate address\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free((void *)child_keys, num_allocated * sizeof(key_pair_t *));
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return 1;
			}
			child_keys[addr_and_key_count] = child_key;
			addr_and_key_count++;
		}
		g_free((void *)change_key, sizeof(key_pair_t));
	}
	g_free((void *)account_key, sizeof(key_pair_t));
	
	// Match UTXO inputs to private keys	
	for (size_t i = 0; i < num_inputs; i++) {
		for (size_t j = 0; j < addr_and_key_count; j++) {
			if (strcmp(rbf_data->utxos[i]->address, addresses[j]) == 0) {
				rbf_data->utxos[i]->key = child_keys[j];
				child_keys[j] = NULL; // Prevent double-free
				printf("Found matching private key for UTXO index %ld\n", i);
				break;
			} else {
				if (j == addr_and_key_count - 1) {
					fprintf(stderr, "Unable to find matching key for UTXO index %ld\n", i);
					free_addresses_and_keys(addresses, child_keys, addr_and_key_count);
					return 1;
				}
			}
		}
	}
	
	free_addresses_and_keys(addresses, child_keys, addr_and_key_count);
	printf("Successfully matched all UTXO inputs to private keys.\n");
	return 0;
}

int build_rbf_transaction(rbf_data_t *rbf_data, char **raw_tx_hex, uint8_t **segwit_tx, size_t *segwit_len) {
	if (!rbf_data) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
//printf("Raw Tx Hex: %s\n", rbf_data->raw_tx_hex);
	long long input_sum = 0;
	for (int i = 0; i < rbf_data->num_inputs; i++) {
		input_sum += rbf_data->utxos[i]->amount;
	}
	long long output_sum = 0;
	for (int i = 0; i < rbf_data->num_outputs; i++) {
		output_sum += rbf_data->outputs[i]->amount;
	}
	long long fee_difference = rbf_data->new_fee - rbf_data->old_fee;
printf("Fee Difference: %d\n", (int)fee_difference);
	if (input_sum < output_sum + fee_difference) {
		fprintf(stderr, "Insufficient funds, %lld < %lld\n", input_sum, output_sum + fee_difference);
		return 1;
	}
	// Estimate buffer size (extra for safety)
	size_t max_size = 4 + 2 + 9 + rbf_data->num_inputs * 40 + 9 + rbf_data->num_outputs * 25 + rbf_data->num_inputs * 4 + 4 + 1000;
	uint8_t *buffer = (uint8_t *)g_malloc(max_size);
	if (!buffer) {
		fprintf(stderr, "Failed to allocate tx buffer\n");
		return 1;
	}
	size_t pos = 0;
	// Version (2 for segwit)
	encode_uint32_le(TX_VERSION, buffer + pos);
	pos += 4;
	// Marker and buffer[pos++] = 0x00;
	buffer[pos++] = 0x00;
	buffer[pos++] = 0x01;
	// Input count
	uint8_t varint_buf[9];
	size_t varint_len;
	if (encode_varint(rbf_data->num_inputs, varint_buf, &varint_len) != 0) {
		fprintf(stderr, "Failed to encode input count\n");
		g_free((void *)buffer, max_size);
		return 1;
	}	
	memcpy(buffer + pos, varint_buf, varint_len);
	pos += varint_len;
	// Inputs
	for (size_t i = 0; i < rbf_data->num_inputs; i++) {
		utxo_t *utxo = rbf_data->utxos[i];
		// TxId
		uint8_t txid_bytes[32];
		hex_to_bytes(utxo->txid, txid_bytes, 32);
		//reverse_bytes(txid_bytes, 32);
		memcpy(buffer + pos, txid_bytes, 32);
		pos += 32;
		// vout
		encode_uint32_le(utxo->vout, buffer + pos);
		pos += 4;
		// ScriptSig (empty for P2WPKWH)
		buffer[pos++] = 0x00;
		// Sequence
		encode_uint32_le(0xfffffffd, buffer + pos);
		pos += 4;
	}
	// Output count
	if (encode_varint(rbf_data->num_outputs, varint_buf, &varint_len) != 0) {
		fprintf(stderr, "Failed to encode output count\n");
		g_free((void *)buffer, max_size);
		return 1;
	}
	memcpy(buffer + pos, varint_buf, varint_len);
	pos += varint_len;
	// Outputs
	for (size_t i = 0; i < rbf_data->num_outputs; i++) {
		rbf_output_t *output = rbf_data->outputs[i];
		uint8_t script[25];
		size_t script_len;
		if (address_to_scriptpubkey(output->address, script, &script_len) != 0) {
			fprintf(stderr, "Failed to convert recipient address\n");
			g_free((void *)buffer, max_size);
			return 1;
		}
		// Encode amount to be sent
		if (i == rbf_data->num_outputs - 1) {
			encode_uint64_le(output->amount - fee_difference, buffer + pos);	
printf("Last Output's new amount: %lld\n", output->amount - fee_difference);
		} else {
			encode_uint64_le(output->amount, buffer + pos);
		}
		pos += 8;
		// Encode scriptpubkey size
		encode_uint32_le(script_len, buffer + pos);
		pos++;
		// Copy over scriptpubkey
		memcpy(buffer + pos, script, script_len);
		pos += script_len;
	}
	// Locktime
	encode_uint32_le(0, buffer + pos);
	pos += 4;
	// Save segwit transaction (without the marker and flag) for txid after signage
	*segwit_len = pos - 2;
	*segwit_tx = (uint8_t *)g_malloc(*segwit_len);
	if (!*segwit_tx) {
		fprintf(stderr, "Error allocating segwit_tx\n");
		g_free((void *)buffer, max_size);
		return 1;
	}
	memcpy(*segwit_tx, buffer, 4);
	memcpy(*segwit_tx + 4, buffer + 6, pos - 6);
print_bytes_as_hex("Segwit Tx", *segwit_tx, *segwit_len);
	// Convert to hex
	*raw_tx_hex = (char *)g_malloc(pos * 2 + 1);
	if (!*raw_tx_hex) {
		g_free((void *)*segwit_tx, *segwit_len);
		fprintf(stderr, "Failed to allocate raw_tx_hex\n");
		return 1;
	}
	bytes_to_hex(buffer, pos, *raw_tx_hex, pos * 2 + 1);
	g_free((void *)buffer, max_size);
printf("Raw Tx Hex: %s\n", *raw_tx_hex);
	return 0;	
}

int build_transaction(const char *recipient, long long amount, utxo_t **selected, int num_selected, key_pair_t *change_back_key, long long fee, char **raw_tx_hex, uint8_t **segwit_tx, size_t *segwit_len, int rbf) {
	if (!recipient || amount <= 0 || !selected || num_selected <= 0 || fee < 0) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	printf("Building your transaction data...\n");
	// Validate funds
	long long input_sum = 0;
	for (int i = 0; i < num_selected; i++) {
		input_sum += selected[i]->amount;
	}	
	if (input_sum < amount + fee) {
		fprintf(stderr, "Insufficient funds, %lld < %lld\n", input_sum, amount + fee);
		return 1;
	}
	long long change = input_sum - amount - fee;
	int num_outputs = change > 0 ? 2 : 1;
	// Estimate buffer size
	size_t max_size = 4 + 2 + 9 + num_selected * 40 + 9 + num_outputs * 25 + num_selected * 4 + 4 + 1000; // Extra for safety
	uint8_t *buffer = (uint8_t *)g_malloc(max_size);
	if (!buffer) {
		fprintf(stderr, "Failed to allocate tx buffer\n");
		return 1;
	}
	size_t pos = 0;
	// Version (2 for segwit)
	encode_uint32_le(TX_VERSION, buffer + pos);
	pos += 4;
	// Marker and buffer[pos++] = 0x00;
	buffer[pos++] = 0x00;
	buffer[pos++] = 0x01;
	// Input count
	uint8_t varint_buf[9];
	size_t varint_len;
	if (encode_varint(num_selected, varint_buf, &varint_len) != 0) {
		fprintf(stderr, "Failed to encode input count\n");
		g_free((void *)buffer, max_size);
		return 1;
	}	
	memcpy(buffer + pos, varint_buf, varint_len);
	pos += varint_len;
	// Inputs
	for (size_t i = 0; i < num_selected; i++) {
		// TxId
		uint8_t txid_bytes[32];
		hex_to_bytes((*selected)[i].txid, txid_bytes, 32);
		//reverse_bytes(txid_bytes, 32);
		memcpy(buffer + pos, txid_bytes, 32);
		pos += 32;
		// vout
		encode_uint32_le((*selected)[i].vout, buffer + pos);
		pos += 4;
		// ScriptSig (empty for P2WPKWH)
		buffer[pos++] = 0x00;
		// Sequence
		encode_uint32_le(rbf ? 0xfffffffd : 0xffffffff, buffer + pos);
		pos += 4;
	}
	// Output count
	if (encode_varint(num_outputs, varint_buf, &varint_len) != 0) {
		fprintf(stderr, "Failed to encode output count\n");
		g_free((void *)buffer, max_size);
		return 1;
	}
	memcpy(buffer + pos, varint_buf, varint_len);
	pos += varint_len;
	// Outputs
	// Recipient output
	uint8_t script[25];
	size_t script_len;
	if (address_to_scriptpubkey(recipient, script, &script_len) != 0) {
		fprintf(stderr, "Failed to convert recipient address\n");
		g_free((void *)buffer, max_size);
		return 1;
	}
	// Encode amount to be sent
	encode_uint64_le(amount, buffer + pos);
	pos += 8;
	// Encode scriptpubkey size
	encode_uint32_le(script_len, buffer + pos);
	pos++;
	// Copy over scriptpubkey
	memcpy(buffer + pos, script, script_len);
	pos += script_len;
	// Change output
	if (change > 0) {
		if (!change_back_key) {
			fprintf(stderr, "Change required but no change key provided\n");
			g_free((void *)buffer, max_size);
			return 1;
		}
		char change_address[ADDRESS_MAX_LEN];
		if (pubkey_to_address(change_back_key->key_pub_compressed, PUBKEY_LENGTH, change_address, ADDRESS_MAX_LEN) != 0) {
			fprintf(stderr, "Failed to convert change address\n");
			g_free((void *)buffer, max_size);
			return 1;
		}
		if (address_to_scriptpubkey(change_address, script, &script_len) != 0) {
			fprintf(stderr, "Failed to convert change scriptpubkey\n");
			g_free((void *)buffer, max_size);
			return 1;
		}
		// Encode amount to be sent back as change
		encode_uint64_le(change, buffer + pos);
		pos += 8;
		// Encode scriptpubkey size
		encode_uint32_le(script_len, buffer + pos);
		pos++;
		// Copy over scriptpubkey of your change address
		memcpy(buffer + pos, script, script_len);
		pos += script_len;
	}
	// Locktime
	encode_uint32_le(0, buffer + pos);
	pos += 4;

	// Save segwit transaction (without the marker and flag) for txid after signage
	*segwit_len = pos - 2;
	*segwit_tx = (uint8_t *)g_malloc(*segwit_len);
	if (!*segwit_tx) {
		fprintf(stderr, "Error allocating segwit_tx\n");
		g_free((void *)buffer, max_size);
		return 1;
	}
	memcpy(*segwit_tx, buffer, 4);
	memcpy(*segwit_tx + 4, buffer + 6, pos - 6);
print_bytes_as_hex("Segwit Tx", *segwit_tx, *segwit_len);

	// Convert to hex
	*raw_tx_hex = g_malloc(pos * 2 + 1);
	if (!*raw_tx_hex) {
		fprintf(stderr, "Failed to allocate raw_tx_hex\n");
		g_free((void *)buffer, max_size);
		g_free((void *)*segwit_tx, *segwit_len);
		return 1;
	}
	bytes_to_hex(buffer, pos, *raw_tx_hex, pos * 2 + 1);
printf("Raw Tx Hex: %s\n", *raw_tx_hex);
	g_free((void *)buffer, max_size);
	return 0;
}

int construct_scriptcode(uint8_t *pubkeyhash, uint8_t *scriptcode, size_t scriptcode_len) {
	if (!pubkeyhash || scriptcode_len != 26) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	size_t pos = 0;
	scriptcode[0] = 0x19;
	scriptcode[1] = 0x76;
	scriptcode[2] = 0xa9;
	scriptcode[3] = 0x14;
	pos += 4;
	memcpy(scriptcode + pos, pubkeyhash, 20);
	pos += 20;
	scriptcode[pos] = 0x88;
	scriptcode[pos + 1] = 0xac;
	pos += 2;
	if (pos != 26) {
		fprintf(stderr, "Failure constructing scriptcode\n");
		return 1;
	}
print_bytes_as_hex("ScriptCode", scriptcode, 26);
	return 0;
}

int construct_preimage(uint8_t *tx_data, size_t tx_len, utxo_t **selected, int num_selected, uint8_t *sighash) {
	if (!tx_data || !selected || num_selected <= 0) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	size_t pos = 0;
	// Version (4 byte)
	uint8_t version[4];
	memcpy(version, tx_data + pos, 4);
	pos += 4;
	// Skip marker and flag (2 bytes)
	pos += 2;
	// Input count (varint, assuming small, 1 byte)
	int num_inputs = tx_data[pos];
	pos += 1;
	if (num_inputs != num_selected) {
		fprintf(stderr, "Inputs count mismatched with UTXOs selected\n");
		return 1;
	}
	// Parse inputs and serialize outpoints + sequences
	uint8_t *outpoints = (uint8_t *)g_malloc(num_inputs * 36); // 32 txid + 4 vout
	uint8_t *sequences = (uint8_t *)g_malloc(num_inputs * 4);
	if (!outpoints || !sequences) {
		fprintf(stderr, "Failure allocating outpoints and sequences\n");
		return 1;
	}
	size_t outpoints_pos = 0;
	size_t sequences_pos = 0;
	for (int i = 0; i < num_inputs; i++) {
		// TxId (32 bytes)
		memcpy(outpoints + outpoints_pos, tx_data + pos, 32);
		outpoints_pos += 32;
		pos += 32;
		// Vout (4 bytes)
		memcpy(outpoints + outpoints_pos, tx_data + pos, 4);
		outpoints_pos += 4;
		pos += 4;
		// Skip scriptsig
		pos += 1;
		// Sequence (4 bytes)
		memcpy(sequences + sequences_pos, tx_data + pos, 4);
		sequences_pos += 4;
		pos += 4;
	}
	// Hash outpoints
	uint8_t hash_prevouts[32];
	double_sha256(outpoints, num_inputs * 36, hash_prevouts);
	g_free((void *)outpoints, num_inputs * 36);
	// Hash sequences
	uint8_t hash_sequence[32];
	double_sha256(sequences, num_inputs * 4, hash_sequence);
	g_free((void *)sequences, num_inputs * 4);
	// Output count (varint, assume small, 1 byte)
	int num_outputs = tx_data[pos];
	pos += 1;
	// Parse outputs and serialize
	uint8_t *outputs_serialized = (uint8_t *)g_malloc(num_outputs * (8 + 1 + 22)); // Amount (8 bytes) and script ~22 for P2WPKH
	if (!outputs_serialized) {
		fprintf(stderr, "Failed to allocate outputs_serialized\n");
		return 1;
	}
	size_t outputs_pos = 0;
	for (int i = 0; i < num_outputs; i++) {
		// Amount (8 bytes)
		memcpy(outputs_serialized + outputs_pos, tx_data + pos, 8);
print_bytes_as_hex("Output Amount", outputs_serialized + outputs_pos, 8);
		outputs_pos += 8;
		pos += 8;
		// Script length (1 byte)
		uint8_t script_len = tx_data[pos];
		memcpy(outputs_serialized + outputs_pos, &script_len, 1);
		outputs_pos += 1;
		pos += 1;
		// Script (~22 bytes)
		memcpy(outputs_serialized + outputs_pos, tx_data + pos, script_len);
		outputs_pos += script_len;
		pos += script_len;
	}
	uint8_t hash_outputs[32];
	double_sha256(outputs_serialized, outputs_pos, hash_outputs);
	g_free((void *)outputs_serialized, num_inputs * (8 + 1 + 22));
	// Locktime (4 bytes)
	uint8_t locktime[4];
	memcpy(locktime, tx_data + pos, 4);
	pos += 4;
	// Sighash type (4 bytes)
	uint8_t sighash_type [4];
	encode_uint32_le(SIGHASH_ALL, sighash_type);
	// Prepare preimage = 
	// version + hash256(inputs) + hash256(sequences) + (num_inputs * (input(txid + vout)) + scriptcode + amount + sequence) + hash256(outputs) + locktime	
	size_t preimage_len = 4 + 32 + 32 + ((36 + 26 + 8 + 4) * num_inputs) + 32 + 4 + 4; 
	uint8_t *preimage = (uint8_t *)g_malloc(preimage_len);
	if (!preimage) {
		fprintf(stderr, "Failed to allocate preimage\n");
		return 1;
	}
	size_t preimage_pos = 0;
	// Version --REUSABLE
	memcpy(preimage + preimage_pos, version, 4);
printf("PREHASH IMAGE:\n");
print_bytes_as_hex("Version", preimage + preimage_pos, 4);
	preimage_pos += 4;
	// HashPrevouts --REUSABLE
	memcpy(preimage + preimage_pos, hash_prevouts, 32);
print_bytes_as_hex("HashPrevouts", preimage + preimage_pos, 32);
	preimage_pos += 32;
	// HashSequence --REUSABLE
	memcpy(preimage + preimage_pos, hash_sequence, 32);
print_bytes_as_hex("HashSequence", preimage + preimage_pos, 32);
	preimage_pos += 32;
	for (int i = 0; i < num_inputs; i++) {
printf("Outpoint (AKA Inputs)\n");
		// Outpoint (txid + vout per input)
		uint8_t outpoint[36];
		memcpy(outpoint, tx_data + 7, 32); // TxID
		memcpy(outpoint + 32, tx_data + 39, 4); // Vout
		memcpy(preimage + preimage_pos, outpoint, 36);
print_bytes_as_hex("TXID + VOUT", preimage + preimage_pos, 36);
		preimage_pos += 36;
		// ScriptCode (P2WPKH format: 1976a914<hash>88ac)
		uint8_t pubkeyhash[20];
		if (key_to_pubkeyhash((*selected)[i].key, pubkeyhash) != 0) {
			fprintf(stderr, "Error extracting pub key hash\n");
			g_free((void *)preimage, preimage_len);
			return 1;		
		}
		uint8_t scriptcode[26];
		if (construct_scriptcode(pubkeyhash, scriptcode, 26) != 0) {
			fprintf(stderr, "Error constructing scriptcode\n");
			g_free((void *)preimage, preimage_len);
			return 1;
		}
		memcpy(preimage + preimage_pos, scriptcode, 26);
print_bytes_as_hex("Scriptcode", preimage + preimage_pos, 26);
		preimage_pos += 26;
		// Amount
		uint8_t amount[8];
		encode_uint64_le((*selected)[i].amount, amount);
		memcpy(preimage + preimage_pos, amount, 8);
print_bytes_as_hex("Input amount", preimage + preimage_pos, 8);
		preimage_pos += 8;
		// Sequence
		memcpy(preimage + preimage_pos, tx_data + 44, 4); 
print_bytes_as_hex("Sequence", preimage + preimage_pos, 4);
		preimage_pos += 4;
	}
	// HashOutputs --REUSABLE
	memcpy(preimage + preimage_pos, hash_outputs, 32);
print_bytes_as_hex("HashOutputs", preimage + preimage_pos, 32);
	preimage_pos += 32;
	// Locktime --REUSABLE
	memcpy(preimage + preimage_pos, locktime, 4);
print_bytes_as_hex("Locktime", preimage + preimage_pos, 4);
	preimage_pos += 4;
	// Add sig hash type at the end
	memcpy(preimage + preimage_pos, sighash_type, 4);
print_bytes_as_hex("Sighash", preimage + preimage_pos, 4);
	preimage_pos += 4;
print_bytes_as_hex("Preimage", preimage, preimage_pos);
	// Hash256 the entire preimage
	double_sha256(preimage, preimage_pos, sighash);
print_bytes_as_hex("Message (Hashed Preimage)", sighash, 32);
	g_free((void *)preimage, preimage_len);
	return 0; 
}

int sign_preimage_hash(uint8_t *sighash, uint8_t *privkey, uint8_t *witness, size_t *witness_len, uint8_t *pubkey) {
	if (!sighash || !privkey || !pubkey) {
		fprintf(stderr, "Input errors\n");
		return 1;
	}
	// Sign with private key
	gcry_sexp_t priv_sexp, data_sexp, sig_sexp;
	gcry_error_t err;
	err = gcry_sexp_build(&priv_sexp, NULL, "(private-key (ecc (curve secp256k1) (d %b)))", PRIVKEY_LENGTH, privkey);
	if (err) {
		fprintf(stderr, "Failed to build priv_sexp: %s\n", gcry_strerror(err));
		return 1;
	}
	err = gcry_sexp_build(&data_sexp, NULL, "(data (flags raw) (hash-algo sha256) (value %b))", 32, sighash);
	if (err) {
		gcry_sexp_release(priv_sexp);
		fprintf(stderr, "Failed to build data_sexp: %s\n", gcry_strerror(err));
		return 1;
	}
	err = gcry_pk_sign(&sig_sexp, data_sexp, priv_sexp);
	if (err) {
		gcry_sexp_release(data_sexp);
		gcry_sexp_release(priv_sexp);
		fprintf(stderr, "Failed to sign: %s\n", gcry_strerror(err));
		return 1;
	}
	gcry_sexp_t r, s;
	r = gcry_sexp_find_token(sig_sexp, "r", 0);
	s = gcry_sexp_find_token(sig_sexp, "s", 0);
	if (!r || !s) {
		gcry_sexp_release(sig_sexp);
		gcry_sexp_release(data_sexp);
		gcry_sexp_release(priv_sexp);
		fprintf(stderr, "Failed to find r or s in signature\n");
		return 1;
	}
	size_t r_len, s_len;
	const void *r_data = gcry_sexp_nth_data(r, 1, &r_len);
	const void *s_data = gcry_sexp_nth_data(s, 1, &s_len);
	if (!r_data || !s_data || r_len > 33 || s_len > 32) {
		gcry_sexp_release(r);
		gcry_sexp_release(s);
		gcry_sexp_release(sig_sexp);
		gcry_sexp_release(data_sexp);
		gcry_sexp_release(priv_sexp);
		fprintf(stderr, "Invalid r or s data\n");
		return 1;
	}
	// Check for low-S
	uint8_t s_final[32];
	int low_s = is_s_low(s_data, s_len);
	if (!low_s) {
		printf("High S value detected, replacing S with N - S\n");
		const uint8_t curve_order_n[32] = {
		    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
		    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
		    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
		};
		gcry_mpi_t s_mpi, n_mpi, result_mpi;
		s_mpi = gcry_mpi_set_ui(NULL, 0);
		n_mpi = gcry_mpi_set_ui(NULL, 0);
		result_mpi = gcry_mpi_set_ui(NULL, 0);
		gcry_mpi_scan(&s_mpi, GCRYMPI_FMT_USG, s_data, s_len, NULL);
		gcry_mpi_scan(&n_mpi, GCRYMPI_FMT_USG, curve_order_n, 32, NULL);

		// Compute n - s
		gcry_mpi_sub(result_mpi, n_mpi, s_mpi);
		// Convert result back to bytes
		gcry_mpi_print(GCRYMPI_FMT_USG, s_final, 32, &s_len, result_mpi);
		// Release mpi
		gcry_mpi_release(s_mpi);
		gcry_mpi_release(n_mpi);
		gcry_mpi_release(result_mpi);

		if (s_len > 32) {
		    gcry_sexp_release(r);
		    gcry_sexp_release(s);
		    gcry_sexp_release(sig_sexp);
		    gcry_sexp_release(data_sexp);
		    gcry_sexp_release(priv_sexp);
		    fprintf(stderr, "Computed s value too large\n");
		    return 1;
		}
		// Pad with leading zeros if necessary
		if (s_len < 32) {
			memmove(s_final + (32 - s_len), s_final, s_len);
			memset(s_final, 0, 32 - s_len);
			s_len = 32;
		}
	} else {
		memcpy(s_final, s_data, s_len);
		if (s_len < 32) {
			memmove(s_final + (32 - s_len), s_final, s_len);
			memset(s_final, 0, 32 - s_len);
			s_len = 32;
		}	
	}

print_bytes_as_hex("R", r_data, r_len);
print_bytes_as_hex("S", s_final, s_len);
	
	// Strip leading zeros for canon DER
	size_t r_len_stripped = r_len;
	const uint8_t *r_data_stripped = r_data;
	while (r_len_stripped > 0 && *r_data_stripped == 0 && r_len_stripped > 1) {
		r_data_stripped++;
		r_len_stripped--;
	}
	// Add leading zero if high bit is set (avoid negative)
	int r_needs_zero = (r_len_stripped > 0 && (*r_data_stripped & 0x80) != 0);
	
	size_t s_len_stripped = s_len;
	const uint8_t *s_data_stripped = s_final;
	while (s_len_stripped > 0 && *s_data_stripped == 0 && s_len_stripped > 1) {
		s_data_stripped++;
		s_len_stripped--;
	}
	int s_needs_zero = (s_len_stripped > 0 && (*s_data_stripped & 0x80) != 0);		

	// DER encode the signature
	uint8_t encoded_sig[74]; // 2 + 1 + 33 + 1 + 32 + 1
	size_t sig_len = 0;
	size_t pos = 0;
	encoded_sig[pos++] = 0x30;
	size_t content_len = 2 + r_len_stripped + 2 + s_len_stripped; // exclude sighash type
	if (r_needs_zero) content_len++;
	if (s_needs_zero) content_len++;
	encoded_sig[pos++] = content_len;
	// R
	encoded_sig[pos++] = 0x02;
	encoded_sig[pos++] = r_needs_zero ? r_len_stripped + 1 : r_len_stripped;
	if (r_needs_zero) encoded_sig[pos++] = 0x00;
	memcpy(encoded_sig + pos, r_data_stripped, r_len_stripped);
	pos += r_len_stripped;
	// S
	encoded_sig[pos++] = 0x02;
	encoded_sig[pos++] = s_needs_zero ? s_len_stripped + 1 : s_len_stripped;
	if (s_needs_zero) encoded_sig[pos++] = 0x00;
	memcpy(encoded_sig + pos, s_data_stripped, s_len_stripped);
	pos += s_len_stripped;
	// Append signature hash type
	encoded_sig[pos++] = 0x01;
	// Calculate total encoded sig len
	sig_len = pos;
	if (sig_len > 72) {
		fprintf(stderr, "Signature higher than 72 bytes, too large.\n");
		gcry_sexp_release(r);
		gcry_sexp_release(s);
		gcry_sexp_release(sig_sexp);
		gcry_sexp_release(data_sexp);
		gcry_sexp_release(priv_sexp);
		return 1;
	}
	gcry_sexp_release(priv_sexp);
	gcry_sexp_release(sig_sexp);
	gcry_sexp_release(data_sexp);
	gcry_sexp_release(r);
	gcry_sexp_release(s);
printf("Sig Len: %zu\n", sig_len);
print_bytes_as_hex("Signature with sighash", encoded_sig, sig_len);
	// Construct full witness
	pos = 0;
	witness[pos++] = 0x02; // Stack items
	witness[pos++] = sig_len;
	memcpy(witness + pos, encoded_sig, sig_len);
	pos += sig_len;
	witness[pos++] = PUBKEY_LENGTH;
	memcpy(witness + pos, pubkey, PUBKEY_LENGTH);
	pos += PUBKEY_LENGTH;
	*witness_len = pos;
print_bytes_as_hex("Witness", witness, *witness_len);
	return 0;
}

int sign_transaction(char **raw_tx_hex, utxo_t **selected, int num_selected) {
	if (!raw_tx_hex || !selected || num_selected <= 0) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	printf("Signing transaction...\n");
	size_t tx_len = strlen(*raw_tx_hex) / 2;
	uint8_t *tx_data =(uint8_t *)g_malloc(tx_len);
	if (!tx_data) {
		fprintf(stderr, "Failed to allocate tx_data\n");
		return 1;
	}
	hex_to_bytes(*raw_tx_hex, tx_data, tx_len);
	uint8_t sighash[32];
	if (construct_preimage(tx_data, tx_len, selected, num_selected, sighash) != 0) {
		fprintf(stderr, "construct_preimage() failure\n");	
		g_free((void *)tx_data, tx_len);
		return 1;
	}
	// Extract locktime
	uint8_t locktime[4];
	memcpy(locktime, tx_data + tx_len - 4, 4);
	// Append witnesses
	// Allocate a larger array for witness(es)
	size_t new_tx_len = tx_len + (num_selected * 108); // Maximum witness size
	uint8_t *new_tx_data = (uint8_t *)g_malloc(new_tx_len);
	if (!new_tx_data) {
		fprintf(stderr, "Failure to allocate new_tx_data\n");
		g_free((void *)tx_data, tx_len);
		return 1;
	}
	memcpy(new_tx_data, tx_data, tx_len - 4); // Everything except locktime
	g_free((void *)tx_data, tx_len);
	size_t current_pos = tx_len - 4;
	for (int i = 0; i < num_selected; i++) {
		uint8_t witness[108]; // 72 for signature, 33 for pubkey, 3 extra description bytes
		size_t witness_len = 0;
		if (sign_preimage_hash(sighash, (*selected)[i].key->key_priv, witness, &witness_len, (*selected)[i].key->key_pub_compressed) != 0) {
			fprintf(stderr, "Failure to sign preimage hash\n");
			g_free((void *)new_tx_data, new_tx_len);
			return 1;
		}
		// Append to witness
		memcpy(new_tx_data + current_pos, witness, witness_len);
		current_pos += witness_len;
	}
	// Insert locktime at the end after witness
	memcpy(new_tx_data + current_pos, locktime, 4);
	current_pos += 4;
	// Convert back to hex
    	char *new_raw_tx_hex = (char *)g_malloc(current_pos * 2 + 1);
    	if (!new_raw_tx_hex) {
		fprintf(stderr, "Failed to allocate new_raw_tx_hex\n");
		g_free((void *)new_tx_data, new_tx_len);
		return 1;
    	}
    	bytes_to_hex(new_tx_data, current_pos, new_raw_tx_hex, current_pos * 2 + 1);
	new_raw_tx_hex[current_pos * 2] = '\0';
	g_free((void *)new_tx_data, new_tx_len);
    	*raw_tx_hex = new_raw_tx_hex;
printf("Signed hex: %s\n", *raw_tx_hex);
    	return 0;
}

int broadcast_transaction(char *raw_tx_hex, time_t *last_request) {
	CURL *curl = curl_easy_init();
	if (!curl) return 1;
	printf("Broadcasting your transaction...\n");
// Purposely typed wrong to test
	char url[] = "https://000blockchain.info/pushtx";
	char post_data[2048];
	snprintf(post_data, sizeof(post_data), "tx=%s", raw_tx_hex);
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_buffer_t buffer = {0};
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	
	time_t now = time(NULL);
	if (*last_request != 0 && difftime(now, *last_request) < SECS_PER_REQUEST) {
		int sleep_time = SECS_PER_REQUEST - (int)difftime(now, *last_request);
		printf("Rate limit: 1 request per %d seconds...\nWaiting %d seconds...\n", SECS_PER_REQUEST, sleep_time);
		sleep(sleep_time);
	}
	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "CURL request failed\n");
		free(buffer.data);
		return 1;
	}
printf("Response: %s\n", buffer.data);
	// Check response for success
	if (strstr(buffer.data, "Transaction Submitted") == NULL) {
		fprintf(stderr, "Unsuccessful broadcast.\n");
		free(buffer.data);
		return 1;
	}
	printf("Successfully broadcasted transaction.\n");
	free(buffer.data);
	return 0;
}
