/* utxo.c */
#include <curl/curl.h>
#include <jansson.h>
#include "utxo.h"
#include "crypt.h"
#include "hash.h"
#include "query.h"

long long query_utxos(char **addresses, int num_addresses, utxo_t **utxos, int *num_utxos, key_pair_t **child_keys, time_t *last_request) {
	printf("Querying UTXOs...\n");
	long long total_balance = 0;
	int result;
	if (*addresses[0] == '\0' || num_addresses == 0) {
		fprintf(stderr, "Addresses invalid.\n");
		for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    		gcry_free((void *)addresses);
		return -1;
	}
	// Set a curl handle for the data transfer
	CURL *curl = curl_easy_init();
	if (!curl) return -1;
	// Build pipe-separated address list for API
	char addr_list[1024 * 2] = {0};

	for (int i = 0; i < num_addresses; i++) {
		strncat(addr_list, addresses[i], sizeof(addr_list) - strlen(addr_list) - 2);
		if (i < num_addresses - 1) strncat(addr_list, "|", sizeof(addr_list) - strlen(addr_list) - 2);
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
		printf("Rate limit: 1 request per 20 seconds...\nWaiting %d seconds...\n", sleep_time);
		sleep(sleep_time);
	}
    	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
    	curl_easy_cleanup(curl);

    	if (res != CURLE_OK) {
		fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        	for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    		gcry_free((void *)addresses);
		free(buffer.data);
        	return -1;
    	}
	// Parse JSON for total balance
	json_error_t error;
	json_t *root = json_loads(buffer.data, 0, &error);
	free(buffer.data);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    		gcry_free((void *)addresses);
		return -1;
	}
	json_t *unspent_outputs = json_object_get(root, "unspent_outputs");
	if (!json_is_array(unspent_outputs)) {
		fprintf(stderr, "No unspent outputs found\n");
		for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    		gcry_free((void *)addresses);
		json_decref(root);
		return -1;
	}
	// Allocate UTXOs
	*num_utxos = json_array_size(unspent_outputs);
	*utxos = gcry_malloc_secure(*num_utxos * sizeof(utxo_t));
	if (!utxos) {
		fprintf(stderr, "Failure allocating utxos\n");
		for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    		gcry_free((void *)addresses);
		json_decref(root);
		return -1;
	}
	for (int i = 0; i < *num_utxos; i++) {
		json_t *output = json_array_get(unspent_outputs, i);
		json_t *tx_hash = json_object_get(output, "tx_hash");
		json_t *tx_output_n = json_object_get(output, "tx_output_n");
		json_t *value = json_object_get(output, "value");
		if (!json_is_string(tx_hash) || !json_is_integer(tx_output_n) || !json_is_integer(value)) {
			fprintf(stderr, "Invalid UTXO data\n");
			for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    			gcry_free((void *)addresses);
			gcry_free((void *)*utxos);
			*utxos = NULL;
			*num_utxos = 0;
			json_decref(root);
			return -1;
		}
		// Copy values over to utxo struct
		strncpy((*utxos)[i].txid, json_string_value(tx_hash), 64);
		(*utxos)[i].vout = (uint32_t)json_integer_value(tx_output_n);
		(*utxos)[i].amount = (long long)json_integer_value(value);
		total_balance += (*utxos)[i].amount;
		// Convert script to Bech32 address
		json_t *script = json_object_get(output, "script");
		if (!json_string_value(script)) {
			fprintf(stderr, "Invalid UTXO data\n");
			for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    			gcry_free((void *)addresses);
			gcry_free((void *)*utxos);
			*utxos = NULL;
			*num_utxos = 0;
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
			result = pubkeyhash_to_address(hash, 22, utxo_address, ADDRESS_MAX_LEN);
			if (result != 0) {
				fprintf(stderr, "Failure converting witness program to address\n");
				for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
				gcry_free((void *)addresses);
				gcry_free((void *)*utxos);
				*utxos = NULL;
				*num_utxos = 0;
				json_decref(root);
				return -1;
			}
		} else {
			fprintf(stderr, "Invalid script for UTXO\n");
			for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    			gcry_free((void *)addresses);
			gcry_free((void *)*utxos);
			*utxos = NULL;
			*num_utxos = 0;
			json_decref(root);
			return -1;
		}
		(*utxos)[i].key = NULL;
		for (int j = 0; j < num_addresses; j++) {
			if (strncmp(utxo_address, addresses[j], ADDRESS_MAX_LEN) == 0) {
				(*utxos)[i].key = child_keys[j];
				child_keys[j] = NULL; // Preventing double-free
				strncpy((*utxos)[i].address, utxo_address, ADDRESS_MAX_LEN);
				break;
			}
		}
		if (!(*utxos)[i].key) {
			fprintf(stderr, "No matching key for UTXO address %s. Skipping.\n", utxo_address);
		}
	}
	for (int k = 0; k < num_addresses; k++) gcry_free((void *)addresses[k]);
    	gcry_free((void *)addresses);
	json_decref(root);
	return total_balance;
}

long long get_utxos(key_pair_t *master_key, utxo_t **utxos, int *num_utxos, uint32_t account_index, time_t *last_request) {
	if (!master_key || !utxos || !num_utxos) {
		fprintf(stderr, "Invalid inputs\n");
		return -1;
	}
	printf("Gathering UTXO's for account %u...\n", account_index);
	char **addresses = NULL;
	addresses = gcry_malloc_secure(GAP_LIMIT * 2 * sizeof(char *));
	key_pair_t **child_keys = NULL;
	child_keys = gcry_malloc_secure(GAP_LIMIT * 2 * sizeof(key_pair_t *));
	if (!addresses || !child_keys) {
		fprintf(stderr, "Failed to allocate addresses or child keys array\n");
		if (addresses) gcry_free((void *)addresses);
		if (child_keys) gcry_free((void *)child_keys);
		return -1;
	}
	int addr_count = 0;
	int result;
	for (size_t i = 0; i < GAP_LIMIT * 2; i++) {
		// Allocate each of the 40 addresses and NULL it
		char *address = (char *)gcry_malloc_secure(sizeof(char) * ADDRESS_MAX_LEN);
		if (address == NULL) {
			for (int j = 0; j < i; j++) gcry_free((void *)addresses[j]);
			gcry_free((void *)addresses);
			gcry_free((void *)child_keys);
			fprintf(stderr, "Error allocating address\n");
			return -1;
		}
		address[0] = '\0';
		addresses[i] = address;
	}
	key_pair_t *account_key = NULL;
	account_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		for (int j = 0; j < addr_count; j++) gcry_free((void *)addresses[j]);
		gcry_free((void *)addresses);
		gcry_free((void *)child_keys);
		return -1;
	}
	result = derive_from_master_to_account(master_key, account_index, account_key); 
	if (result != 0) {
		fprintf(stderr, "Failure deriving account key\n");
		for (int j = 0; j < addr_count; j++) gcry_free((void *)addresses[j]);
		gcry_free((void *)addresses);
		gcry_free((void *)child_keys);
		zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
		return -1;
	}
	for (uint32_t change = 0; change < 2; change++) { // 0 for external, 1 for internal
		key_pair_t *change_key = NULL;
		change_key = gcry_malloc_secure(sizeof(key_pair_t));
		if (!change_key) {
			fprintf(stderr, "Error gcry_malloc_secure\n");
			for (int j = 0; j < addr_count; j++) gcry_free((void *)addresses[j]);
			gcry_free((void *)addresses);
			gcry_free((void *)child_keys);
			zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
			return -1;
		}
		result = derive_from_account_to_change(account_key, change, change_key);
		if (result != 0) {
			fprintf(stderr, "Failure deriving child key\n");
			for (int j = 0; j < addr_count; j++) gcry_free((void *)addresses[j]);
			gcry_free((void *)addresses);
			gcry_free((void *)child_keys);
			zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
			return -1;
		}
		// For each change (chain), go through all the indexes
		for (uint32_t child_index = 0; child_index < (uint32_t) GAP_LIMIT; child_index++) {
			key_pair_t *child_key = NULL;
			child_key = gcry_malloc_secure(sizeof(key_pair_t));
			if (!child_key) {
				fprintf(stderr, "Error gcry_malloc_secure\n");
				for (int k = 0; k < addr_count; k++) gcry_free((void *)addresses[k]);
				gcry_free((void *)addresses);
				gcry_free((void *)child_keys);
				zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
				return -1;
			}
			result = derive_from_change_to_child(change_key, child_index, child_key);
			if (result != 0) {
				fprintf(stderr, "Failed to derive child key\n");
				for (int k = 0; k < addr_count; k++) gcry_free((void *)addresses[k]);
				gcry_free((void *)addresses);
				gcry_free((void *)child_keys);
				zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return -1;
			}
			result = pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, addresses[addr_count], ADDRESS_MAX_LEN);
			if (result != 0) {
				fprintf(stderr, "Failed to generate address\n");
				for (int k = 0; k < addr_count; k++) gcry_free((void *)addresses[k]);
				gcry_free((void *)addresses);
				gcry_free((void *)child_keys);
				zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return -1;
			}
			child_keys[addr_count] = child_key;
			addr_count++;
		}
		zero_and_gcry_free((void *)change_key, sizeof(key_pair_t));
	}
	zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
    	return query_utxos(addresses, addr_count, utxos, num_utxos, child_keys, last_request);	
}

static int compare_utxos(const void *a, const void *b) {
	const utxo_t *utxo_a = (const utxo_t *)a;
	const utxo_t *utxo_b = (const utxo_t *)b;
	if (utxo_a->amount > utxo_b->amount) return -1;
	if (utxo_a->amount < utxo_b->amount) return 1;
	return 0;
}

int select_coins(utxo_t *utxos, int num_utxos, long long amount, long long fee, utxo_t **selected, int *num_selected, long long *input_sum) {
	// Greedy
	if (!utxos || num_utxos <= 0 || !selected || !num_selected || !input_sum || amount <= 0 || fee <= 0) {
		fprintf(stderr, "Invalid input\n");
		return 1;
	}
	printf("Preparing the most optimal UTXO's set for your transaction...\n");
	long long total_available = 0;
	for (int i = 0; i < num_utxos; i++) {
		if (utxos[i].amount < 0) {
			fprintf(stderr, "Invalid UTXO amount at index %d\n", i);
			return 1;
		}
		total_available += utxos[i].amount;
	}
	if (total_available < amount + fee) {
		fprintf(stderr, "Insufficient funds: %lld available, %lld needed.\n", total_available, amount + fee);
		return 1;
	}
	utxo_t *sorted_utxos = gcry_malloc_secure(num_utxos * sizeof(utxo_t));
	if (!sorted_utxos) {
		fprintf(stderr, "Failed to allocate sorted utxos\n");
		return 1;
	}
	memcpy(sorted_utxos, utxos, num_utxos * sizeof(utxo_t));
	qsort(sorted_utxos, num_utxos, sizeof(utxo_t), compare_utxos);

	// Select greedily
	long long target = amount + fee;
	int count = 0;
	for (int i = 0; i < num_utxos && *input_sum < target; i++) {
		*input_sum += sorted_utxos[i].amount;
		count++;
	}
	*selected = gcry_malloc_secure(count * sizeof(utxo_t));
	if (!selected) {
		fprintf(stderr, "Failed to allocate selected UTXO\n");
		gcry_free(sorted_utxos);
		return 1;
	}
	memcpy(*selected, sorted_utxos, count * sizeof(utxo_t));
	*num_selected = count;
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

int build_transaction(const char *recipient, long long amount, utxo_t **selected, int num_selected, key_pair_t *change_back_key, long long fee, char **raw_tx_hex, uint8_t **segwit_tx, size_t *segwit_len) {
	if (!recipient || amount <= 0 || !selected || num_selected <= 0 || fee < 0) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	printf("Building your transaction data...\n");
	// Validate funds
	long long input_sum = 0;
	for (int i = 0; i < num_selected; i++) {
		if ((*selected)[i].amount < 0) {
			fprintf(stderr, "Invalid UTXO amount at index %d\n", i);
			return 1;
		}
		input_sum += (*selected)[i].amount;
	}	
	if (input_sum < amount + fee) {
		fprintf(stderr, "Insufficient funds, %lld < %lld\n", input_sum, amount + fee);
		return 1;
	}
	long long change = input_sum - amount - fee;
	int num_outputs = change > 0 ? 2 : 1;
	// Estimate buffer size
	size_t max_size = 4 + 2 + 9 + num_selected * 40 + 9 + num_outputs * 25 + num_selected * 4 + 4 + 1000; // Extra for safety
	uint8_t *buffer = (uint8_t *)malloc(max_size);
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
		free(buffer);
		fprintf(stderr, "Failed to encode input count\n");
		return 1;
	}	
	memcpy(buffer + pos, varint_buf, varint_len);
	pos += varint_len;
	// Inputs
	for (int i = 0; i < num_selected; i++) {
		// TxId (reversed)
		uint8_t txid_bytes[32];
		hex_to_bytes((*selected)[i].txid, txid_bytes, 32);
		for (int j = 0; j < 32; j++) {
			buffer[pos + j] = txid_bytes[31 - j];
		}
		pos += 32;
		// vout
		encode_uint32_le((*selected)[i].vout, buffer + pos);
		pos += 4;
		// ScriptSig (empty for P2WPKWH)
		buffer[pos++] = 0x00;
		// Sequence
		encode_uint32_le(0xffffffff, buffer + pos);
		pos += 4;
	}
	// Output count
	if (encode_varint(num_outputs, varint_buf, &varint_len) != 0) {
		free(buffer);
		fprintf(stderr, "Failed to encode output count\n");
		return 1;
	}
	memcpy(buffer + pos, varint_buf, varint_len);
	pos += varint_len;
	// Outputs
	// Recipient output
	uint8_t script[25];
	size_t script_len;
	if (address_to_scriptpubkey(recipient, script, &script_len) != 0) {
		free(buffer);
		fprintf(stderr, "Failed to convert recipient address\n");
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
			free(buffer);
			fprintf(stderr, "Change required but no change key provided\n");
			return 1;
		}
		char change_address[ADDRESS_MAX_LEN];
		if (pubkey_to_address(change_back_key->key_pub_compressed, PUBKEY_LENGTH, change_address, ADDRESS_MAX_LEN) != 0) {
			free(buffer);
			fprintf(stderr, "Failed to convert change address\n");
			return 1;
		}
		if (address_to_scriptpubkey(change_address, script, &script_len) != 0) {
			free(buffer);
			fprintf(stderr, "Failed to convert change scriptpubkey\n");
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
	*segwit_tx = (uint8_t *)malloc(*segwit_len);
	if (!*segwit_tx) {
		fprintf(stderr, "Error allocating segwit_tx\n");
		return 1;
	}
	memcpy(*segwit_tx, buffer, 4);
	memcpy(*segwit_tx + 4, buffer + 6, pos - 6);
print_bytes_as_hex("Segwit Tx", *segwit_tx, *segwit_len);

	// Convert to hex
	*raw_tx_hex = malloc(pos * 2 + 1);
	if (!raw_tx_hex) {
		free(buffer);
		fprintf(stderr, "Failed to allocate raw_tx_hex\n");
		return 1;
	}
	if (bytes_to_hex(buffer, pos, *raw_tx_hex, pos * 2 + 1) != 0) {
		free(buffer);
		free(*raw_tx_hex);
		*raw_tx_hex = NULL;
		fprintf(stderr, "Failed to convert buffer to hex\n");
		return 1;
	}
printf("Raw Tx Hex: %s\n", *raw_tx_hex);
		
	free(buffer);
	return 0;
}

int construct_scriptcode(uint8_t *pubkeyhash, char *scriptcode) {
	if (!pubkeyhash) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	strcpy(scriptcode, "1976a914");
	bytes_to_hex(pubkeyhash, 20, scriptcode + 8, 41);
	strcat(scriptcode, "88ac");
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
		free(tx_data);
		return 1;
	}
	// Parse inputs and serialize outpoints + sequences
	uint8_t *outpoints = malloc(num_inputs * 36); // 32 txid + 4 vout
	uint8_t *sequences = malloc(num_inputs * 4);
	if (!outpoints || !sequences) {
		free(tx_data);
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
	free(outpoints);
	// Hash sequences
	uint8_t hash_sequence[32];
	double_sha256(sequences, num_inputs * 4, hash_sequence);
	free(sequences);
	// Output count (varint, assume small, 1 byte)
	int num_outputs = tx_data[pos];
	pos += 1;
	// Parse outputs and serialize
	uint8_t *outputs_serialized = malloc(num_outputs * (8 + 1 + 22)); // Amount (8 bytes) and script ~22 for P2WPKH
	if (!outputs_serialized) {
		free(tx_data);
		fprintf(stderr, "Failed to allocate outputs_serialized\n");
		return 1;
	}
	size_t outputs_pos = 0;
	for (int i = 0; i < num_outputs; i++) {
		// Amount (8 bytes)
		memcpy(outputs_serialized + outputs_pos, tx_data + pos, 8);
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
	free(outputs_serialized);
	// Locktime (4 bytes)
	uint8_t locktime[4];
	memcpy(locktime, tx_data + pos, 4);
	pos += 4;
	// Sighash type (4 bytes)
	uint8_t sighash_type [4];
	encode_uint32_le(SIGHASH_ALL, sighash_type);
	// Prepare preimage = 
	// version + hash256(inputs) + hash256(sequences) + (num_inputs * (input(txid + vout)) + scriptcode + amount + sequence) + hash256(outputs) + locktime	
	size_t preimage_len = 4 + 32 + 32 + ((36 + 25 + 8 + 4) * num_inputs) + 32 + 4 + 4; 
	uint8_t *preimage = malloc(preimage_len);
	if (!preimage) {
		free(tx_data);
		fprintf(stderr, "Failed to allocate preimage\n");
		return 1;
	}
	size_t preimage_pos = 0;
	// Version
	memcpy(preimage + preimage_pos, version, 4);
	preimage_pos += 4;
	// HashPrevouts
	memcpy(preimage + preimage_pos, hash_prevouts, 32);
	preimage_pos += 32;
	// HashSequence
	memcpy(preimage + preimage_pos, hash_sequence, 32);
	preimage_pos += 32;
	for (int i = 0; i < num_inputs; i++) {
		// Outpoint (txid + vout per input)
		uint8_t outpoint[36];
		memcpy(outpoint, tx_data + 6, 32); // TxID
		memcpy(outpoint + 32, tx_data + 38, 4); // vout
		memcpy(preimage + preimage_pos, outpoint, 36);
		preimage_pos += 36;
		// ScriptCode (P2PKH format: 1976a914<hash>88ac)
		uint8_t pubkeyhash[20];
		if (key_to_pubkeyhash((*selected)[i].key, pubkeyhash) != 0) {
			free(tx_data);
			fprintf(stderr, "Error extracting pub key hash\n");
			return 1;		
		}
		char scriptcode[50];
		if (construct_scriptcode(pubkeyhash, scriptcode) != 0) {
			free(tx_data);
			fprintf(stderr, "Error constructing scriptcode\n");
			return 1;
		}
		uint8_t scriptcode_bytes[25];
		hex_to_bytes(scriptcode, scriptcode_bytes, 25);
		memcpy(preimage + preimage_pos, scriptcode_bytes, 25);
		preimage_pos += 25;
		// Amount
		uint8_t amount[8];
		encode_uint64_le((*selected)[i].amount, amount);
		memcpy(preimage + preimage_pos, amount, 8);
		preimage_pos += 8;
		// Sequence
		memcpy(preimage + preimage_pos, tx_data + 43, 4); 
		preimage_pos += 4;
	}
	// HashOutputs
	memcpy(preimage + preimage_pos, hash_outputs, 32);
	preimage_pos += 32;
	// Locktime
	memcpy(preimage + preimage_pos, locktime, 4);
	preimage_pos += 4;
	// Add sig hash type at the end
	memcpy(preimage + preimage_pos, sighash_type, 4);
	preimage_pos += 4;
	// Sighash type
	double_sha256(preimage, preimage_pos, sighash);
	free(preimage);
	return 0; 
}

int sign_preimage_hash(uint8_t *sighash, uint8_t *privkey, uint8_t *witness, size_t *witness_len, uint8_t *pubkey) {
	if (!sighash || !privkey || !pubkey) {
		fprintf(stderr, "Input errors\n");
		return 1;
	}
	uint8_t encoded_sig[72];
	size_t sig_len = 0;
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
	// DER encode the signature
	encoded_sig[0] = 0x30;
	encoded_sig[1] = r_len + s_len + 4;
	encoded_sig[2] = 0x02;
	encoded_sig[3] = r_len;
	memcpy(4 + encoded_sig, r_data, r_len);
	encoded_sig[4 + r_len] = 0x02;
	encoded_sig[5 + r_len] = s_len;
	memcpy(6 + encoded_sig + r_len, s_data, s_len);
	// Append signature hash type
	encoded_sig[6 + r_len + s_len] = 0x01;
	// Calculate total encoded sig len
	sig_len = 7 + r_len + s_len;
	//encoded_sig[sig_len] = '\0';
	gcry_sexp_release(priv_sexp);
	gcry_sexp_release(sig_sexp);
	gcry_sexp_release(r);
	gcry_sexp_release(s);
	// Construct full witness
	witness[0] = 0x02;
	witness[1] = sig_len;

	memcpy(2 + witness, encoded_sig, sig_len);
	witness[2 + sig_len] = PUBKEY_LENGTH;
	memcpy(3 + witness + sig_len, pubkey, PUBKEY_LENGTH);
	*witness_len = 3 + sig_len + PUBKEY_LENGTH;
	return 0;
}

int sign_transaction(char **raw_tx_hex, utxo_t **selected, int num_selected) {
	if (!raw_tx_hex || !selected || num_selected <= 0) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	printf("Signing transaction...\n");
	size_t tx_len = strlen(*raw_tx_hex) / 2;
	uint8_t *tx_data = malloc(tx_len);
	if (!tx_data) {
		fprintf(stderr, "Failed to allocate tx_data\n");
		return 1;
	}
	hex_to_bytes(*raw_tx_hex, tx_data, tx_len);
	uint8_t sighash[32];
	if (construct_preimage(tx_data, tx_len, selected, num_selected, sighash) != 0) {
		fprintf(stderr, "construct_preimage() failure\n");	
		return 1;
	}
	// Extract locktime
	uint8_t locktime[4];
	memcpy(locktime, tx_data + tx_len - 4, 4);
	// Append witnesses
	size_t witness_pos = tx_len - 4; // Append at end (before locktime)
	// Reallocate to larger array for witness(es)
	size_t new_tx_len = tx_len + (num_selected * 108) - 1; // Approx. witness size
	uint8_t *new_tx_data = (uint8_t *)realloc(tx_data, new_tx_len);
	if (!new_tx_data) {
		free(tx_data);
		fprintf(stderr, "Failure to allocate new_tx_data\n");
		return 1;
	}
	for (int i = 0; i < num_selected; i++) {
		uint8_t witness[108];
		size_t witness_len = 0;
		if (sign_preimage_hash(sighash, (*selected)[i].key->key_priv, witness, &witness_len, (*selected)[i].key->key_pub_compressed) != 0) {
			fprintf(stderr, "Failure to sign preimage hash\n");
			return 1;
		}
		// Append to witness
		memcpy(new_tx_data + witness_pos, witness, witness_len);
		witness_pos += witness_len;
	}
	// Insert locktime at the end after witness
	memcpy(new_tx_data + witness_pos, locktime, 4);
	// Convert back to hex
    	char *new_raw_tx_hex = malloc(new_tx_len * 2);
    	if (!new_raw_tx_hex) {
		free(new_tx_data);
		fprintf(stderr, "Failed to allocate new_raw_tx_hex\n");
		return 1;
    	}
    	bytes_to_hex(new_tx_data, new_tx_len, new_raw_tx_hex, new_tx_len * 2);
	
    	*raw_tx_hex = new_raw_tx_hex;
printf("Signed hex: %s\n", *raw_tx_hex);
	free(new_tx_data);
    	return 0;
}

int broadcast_transaction(char **raw_tx_hex, time_t *last_request) {
	CURL *curl = curl_easy_init();
	if (!curl) return -1;
	printf("Broadcasting your transaction...\n");
// Purposely wrong URL to not send real transaction yet, remove 00 when needed
	char url[] = "https://00blockchain.info/pushtx";
	char post_data[2048];
	snprintf(post_data, sizeof(post_data), "tx=%s", *raw_tx_hex);
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	curl_easy_setopt(curl, CURLOPT_POST, 1L);
	curl_buffer_t buffer = {0};
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	
	time_t now = time(NULL);
	if (*last_request != 0 && difftime(now, *last_request) < SECS_PER_REQUEST) {
		int sleep_time = SECS_PER_REQUEST - (int)difftime(now, *last_request);
		printf("Rate limit: 1 request per 20 seconds...\nWaiting %d seconds...\n", sleep_time);
		sleep(sleep_time);
	}
	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "CURL request failed\n");
		free(buffer.data);
		return -1;
	}
	// Check response for success
	if (strstr(buffer.data, "Transaction Submitted") == NULL) {
		free(buffer.data);
		fprintf(stderr, "Unsuccessful broadcast.\n");
		return -1;
	}
	printf("Successfully broadcasted transaction.\n");
	free(buffer.data);
	return 0;
}
