/* query.c */
#include <jansson.h>
#include <curl/curl.h>
#include "query.h"
#include "wallet.h"
#include "hash.h"
#include "memory.h"

// Matching the parameters prototype of how curl expects their callback function
size_t curl_write_callback_func(void *contents, size_t size, size_t nmemb, void *userdata) {
	// Must match and return this size (bytes) for 'success'
	size_t realsize = size * nmemb;
	curl_buffer_t *mem = (curl_buffer_t *)userdata;
	// Reallocate memory to accomodate new chunk of data being transferred
	char *ptr = realloc(mem->data, mem->size + realsize + 1);
	if (!ptr) return 0;
	mem->data = ptr;
	// Add new chunk of data to the next empty byte slot memory
	memcpy(&(mem->data[mem->size]), contents, realsize);
	// Update size of data buffer so far and null terminate it
	mem->size += realsize;
	mem->data[mem->size] = 0;
	return realsize;
}

int set_curl_run_curl(CURL *curl, char *url, curl_buffer_t *buffer, time_t *last_request) {
	// Set the behaviors for the curl handle
	curl_easy_setopt(curl, CURLOPT_URL, url);
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
    	curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);

	time_t now = time(NULL);
	if (*last_request != 0 && difftime(now, *last_request) < SECS_PER_REQUEST) {
		int sleep_time = SECS_PER_REQUEST - (int)difftime(now, *last_request);
		printf("Rate limit: 1 request per %d seconds...\nWaiting %d seconds...\n", SECS_PER_REQUEST, sleep_time);
		sleep(sleep_time);
	}
	// Perform network transfer
    	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
    	curl_easy_cleanup(curl);

    	if (res != CURLE_OK) {
		fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        	free(buffer->data);
        	return 1;
    	}
	return 0;
}

int init_curl(CURL **curl) {
	*curl = curl_easy_init();
	if (!*curl) {
		fprintf(stderr, "Init Curl failure\n");
		return 1;
	}
	return 0;
}

double get_bitcoin_price(time_t *last_request) {
	CURL *curl = NULL; 
	int result = init_curl(&curl);
	if (result != 0) return 1;

	char url[] = "https://blockchain.info/ticker";
	
	curl_buffer_t buffer = {0};
	result = set_curl_run_curl(curl, url, &buffer, last_request);
	if (result != 0) return 1;

	json_error_t error;
    	json_t *root = json_loads(buffer.data, 0, &error);
    	free(buffer.data);
    	if (!root) {
        	fprintf(stderr, "JSON parse error: %s\n", error.text);
        	return 1.0;
    	}
    	// Extract USD price (last)
    	json_t *usd = json_object_get(root, "USD");
    	if (!json_is_object(usd)) {
        	fprintf(stderr, "Failed to find USD object in JSON\n");
        	json_decref(root);
        	return 1.0;
    	}
    	json_t *last = json_object_get(usd, "last");
    	if (!json_is_number(last)) {
        	fprintf(stderr, "Failed to find last price in USD object\n");
        	json_decref(root);
        	return 1.0;
    	}
    	double price = json_number_value(last);
    	json_decref(root);
    	return price;
}

int init_curl_and_addresses(const char **addresses, int num_addresses, curl_buffer_t *buffer, time_t *last_request) {
	CURL *curl = NULL;
	// Set a curl handle for the data transfer
	int result = init_curl(&curl);
	if (result != 0) return 1;

	// Build pipe-separated address list for API
	char addr_list[1024 * 2] = {0};
	for (int i = 0; i < num_addresses; i++) {
		strncat(addr_list, addresses[i], sizeof(addr_list) - strlen(addr_list) - 2);
		if (i < num_addresses - 1) strncat(addr_list, "|", sizeof(addr_list) - strlen(addr_list) - 2);
	}
	char url[2048];
	snprintf(url, sizeof(url), "https://blockchain.info/multiaddr?active=%s", addr_list);

	// Set the behaviors for the curl handle
	result = set_curl_run_curl(curl, url, buffer, last_request);
	if (result != 0) return 1;
	return 0;
}

int estimate_transaction_size(int num_inputs, int num_outputs) {
	// Non-witness data
	int non_witness = 4 + 2 + 1 + 1 + (num_inputs * 41) + (num_outputs * 33) + 4;
	// Witness data (discounted by 1/4 for SegWit)
	double witness = num_inputs * 108.0 / 4.0;
	return (int)ceil(non_witness + witness);
}

int get_fee_rate(long long *regular_rate, long long *priority_rate, time_t *last_request) {
	printf("Fetching miners fee rate...\n");
	CURL *curl = NULL;
	if (init_curl(&curl) != 0) return 1;

	char url[] = "https://mempool.space/api/v1/fees/recommended";
	curl_buffer_t buffer = {0};
	
	if (set_curl_run_curl(curl, url, &buffer, last_request) != 0) return 1;
	
	json_error_t error;
	json_t *root = json_loads(buffer.data, 0, &error);
	free(buffer.data);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		return 1;
	}
	json_t *priority = json_object_get(root, "fastestFee");
	if (!json_is_integer(priority)) {
		fprintf(stderr, "Unable to find priority fee rate in JSON\n");
		json_decref(root);
		return 1;
	}
	json_t *regular = json_object_get(root, "hourFee");
	if (!json_is_integer(regular)) {
		fprintf(stderr, "Unable to find regular fee rate in JSON\n");
		json_decref(root);
		return 1;
	}
	*regular_rate = (long long)json_integer_value(regular);
	*priority_rate = (long long)json_integer_value(priority);
	json_decref(root);
	return 0;
}

int fetch_rbf_raw_tx_hex(char *tx_id, rbf_data_t *rbf_data, time_t *last_request) {
	if (!tx_id || !rbf_data) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	CURL *curl = NULL;
	if (init_curl(&curl) != 0) {
		fprintf(stderr, "Curl init failure\n");
		return 1;
	}
	char url[2048];
	snprintf(url, sizeof(url), "https://mempool.space/api/tx/%s/hex", tx_id);
	curl_buffer_t buffer = {0};
	if (set_curl_run_curl(curl, url, &buffer, last_request) != 0) {
		return 1;
	}
	
	if (buffer.size < 10 || buffer.size >= 1000 || !buffer.data) {
		fprintf(stderr, "Invalid raw transaction hex\n");
		if (buffer.data) free(buffer.data);
		return 1;
	}	
	strncpy(rbf_data->raw_tx_hex, buffer.data, buffer.size);
	rbf_data->raw_tx_hex[buffer.size] = '\0';
	free(buffer.data);
printf("Raw TX: %s\n", rbf_data->raw_tx_hex);
	return 0;
}

int query_rbf_transaction(char *tx_id, rbf_data_t **rbf_data, time_t *last_request) {
	if (!tx_id) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	CURL *curl = NULL;
	int result = init_curl(&curl);
	if (result != 0) {
		fprintf(stderr, "Curl init failure\n");
		return 1;
	}
	char url[2048];
	snprintf(url, sizeof(url), "https://mempool.space/api/tx/%s", tx_id);
	curl_buffer_t buffer = {0};
	result = set_curl_run_curl(curl, url, &buffer, last_request);
	if (result != 0) return 1;
	
	json_error_t error;
	json_t *root = json_loads(buffer.data, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		free(buffer.data);
		return 1;
	}
	free(buffer.data);
	// Check if confirmed
	json_t *status = json_object_get(root, "status");
	json_t *confirmed = json_object_get(status, "confirmed");
	(*rbf_data)->unconfirmed = json_is_false(confirmed) ? 1 : 0;
	// Copy over TXID
	strncpy((*rbf_data)->txid, tx_id, 64);
	reverse_hex((*rbf_data)->txid, 64);
	(*rbf_data)->txid[strlen(tx_id)] = '\0';
	// Extract inputs
	json_t *vin_array = json_object_get(root, "vin");
	if (json_is_array(vin_array)) {
		(*rbf_data)->num_inputs = json_array_size(vin_array);
	} else {
		fprintf(stderr, "Unable to read vin array input\n");
		json_decref(root);
		return 1;
	}
	(*rbf_data)->utxos = (utxo_t **)g_calloc((*rbf_data)->num_inputs * sizeof(utxo_t *));	
	if (!(*rbf_data)->utxos) {
		fprintf(stderr, "Failure allocating utxos\n");
		json_decref(root);
		return 1;
	}
	size_t vin_index;
	json_t *vin_item;
	json_array_foreach(vin_array, vin_index, vin_item) {
		utxo_t *utxo = (utxo_t *)g_malloc(sizeof(utxo_t));
		if (!utxo) {
			fprintf(stderr, "Failure allocating utxo\n");
			free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, vin_index);
			json_decref(root);
			return 1;
		}
		json_t *id = json_object_get(vin_item, "txid");
		json_t *vout = json_object_get(vin_item, "vout");
		if (json_is_string(id) && json_is_integer(vout)) {
			strncpy(utxo->txid, json_string_value(id), 64);
			utxo->txid[64] = '\0';
			utxo->vout = (uint32_t)json_integer_value(vout);
			json_t *prevout = json_object_get(vin_item, "prevout");
			if (prevout && json_is_object(prevout)) {
				json_t *addr = json_object_get(prevout, "scriptpubkey_address");	
				strncpy(utxo->address, json_string_value(addr), strlen(json_string_value(addr)));
				utxo->address[strlen(json_string_value(addr))] = '\0';
				utxo->vout = (uint32_t)json_integer_value(vout);
				json_t *value = json_object_get(prevout, "value");
				utxo->amount = (long long)json_integer_value(value);
			} else {
				fprintf(stderr, "Missing or invalid prevout in vin item %zu\n", vin_index);
				free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, vin_index);
				json_decref(root);
				return 1;
			}
		} else {
			fprintf(stderr, "Unable to read input UTXOs\n");
			free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, vin_index);
			json_decref(root);
			return 1;
		}
		(*rbf_data)->utxos[vin_index] = utxo;
	}
	// Extract outputs
	json_t *vout_array = json_object_get(root, "vout");
	if (json_is_array(vout_array)) {
		(*rbf_data)->num_outputs = json_array_size(vout_array);
	} else {
		fprintf(stderr, "Unable to read num of outputs\n");
		free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, (size_t)(*rbf_data)->num_inputs);
		json_decref(root);
		return 1;
	}
	size_t vout_index;
	json_t *vout_item;
	(*rbf_data)->outputs = (rbf_output_t **)g_calloc((*rbf_data)->num_outputs * sizeof(rbf_output_t *));
	json_array_foreach(vout_array, vout_index, vout_item) {
		rbf_output_t *output = (rbf_output_t *)g_malloc(sizeof(rbf_output_t));
		json_t *s = json_object_get(vout_item, "scriptpubkey");
		json_t *addr = json_object_get(vout_item, "scriptpubkey_address");
		if (json_is_string(s) && json_is_string(addr)) {
			strncpy(output->address, json_string_value(addr), ADDRESS_MAX_LEN - 1);
			output->address[strlen(json_string_value(addr))] = '\0';
		} else {
			fprintf(stderr, "Unable to read output address\n");
			free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, (size_t)(*rbf_data)->num_inputs);
			free_rbf_outputs_array((*rbf_data)->outputs, (size_t)vout_index);
			json_decref(root);
			return 1;
		}
		json_t *value = json_object_get(vout_item, "value");
		if (json_is_integer(value)) {
			output->amount = json_integer_value(value);
		} else {
			fprintf(stderr, "Unable to read output value\n");
			free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, (size_t)(*rbf_data)->num_inputs);
			free_rbf_outputs_array((*rbf_data)->outputs, (size_t)vout_index);
			json_decref(root);
			return 1;
		}
		(*rbf_data)->outputs[vout_index] = output;
	}	
	// Fee
	json_t *fee = json_object_get(root, "fee");
	if (json_is_integer(fee)) {
		(*rbf_data)->old_fee = json_integer_value(fee);
	} else {
		fprintf(stderr, "Unable to read fee\n");
		free_utxos_array((*rbf_data)->utxos, &(*rbf_data)->num_inputs, (size_t)(*rbf_data)->num_inputs);
		free_rbf_outputs_array((*rbf_data)->outputs, (*rbf_data)->num_outputs);
		json_decref(root);
		return 1;
	}
	(*rbf_data)->raw_tx_hex = (char *)g_malloc(MAX_RAW_TX_HEX);
	printf("Successfully queried RBF transaction data.\n");
	json_decref(root);
	return 0;
}

int parse_json_for_any_transaction(char *json_data) {
	json_error_t error;
	json_t *root = json_loads(json_data, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		return 1;
	}
	json_t *addresses_array = json_object_get(root, "addresses");
	if (json_is_array(addresses_array)) {
		for (size_t i = 0; i < json_array_size(addresses_array); i++) {
			json_t *addr_obj = json_array_get(addresses_array, i);
			json_t *n_tx = json_object_get(addr_obj, "n_tx");
			if (json_is_integer(n_tx)) {
				int n = json_integer_value(n_tx);
				if (n > 0) {
					json_decref(root);
					return 1;
				}
			}
		}
	}
	json_decref(root);
	return 0;
}

long long parse_json_for_total_balance(char *json_data) {
	// Parse JSON for total balance
	long long total_balance = 0;
	json_error_t error;
	json_t *root = json_loads(json_data, 0, &error);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		return 1;
	}
	json_t *addresses_array = json_object_get(root, "addresses");
	if (json_is_array(addresses_array)) {
		for (size_t i = 0; i < json_array_size(addresses_array); i++) {
			json_t *addr_obj = json_array_get(addresses_array, i);
			json_t *balance = json_object_get(addr_obj, "final_balance");
			if (json_is_integer(balance)) {
				total_balance += json_integer_value(balance);
			}
		}
	}
	json_decref(root);
	return total_balance;
}

// Get total balance for a list of addresses (in satoshis)
long long get_balance(const char **addresses, int num_addresses, time_t *last_request) {
	printf("Querying the blockchain for 20 Bech32-P2WPKH address indexes (external and internal chain) associated with this wallet account...\n");
	if (*addresses[0] == '\0' || num_addresses == 0) {
		fprintf(stderr, "Addresses invalid.\n");
		return 1;
	}
	curl_buffer_t buffer = {0};
	int result = init_curl_and_addresses(addresses, num_addresses, &buffer, last_request);
	if (result != 0) {
		fprintf(stderr, "Failed to initialize curl and addresses\n");
		return 1;
	}
	long long balance = parse_json_for_total_balance(buffer.data);
	free(buffer.data);
	return balance;
}

long long get_account_balance(key_pair_t *master_key, uint32_t account_index, time_t *last_request) {
	if (!master_key) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	char **addresses = NULL;
	size_t num_allocated = GAP_LIMIT * 2;
	addresses = (char **)g_malloc(num_allocated * sizeof(char *));
	if (!addresses) {
		fprintf(stderr, "Failed to allocate addresses array\n");
		return 1;
	}
	for (size_t i = 0; i < num_allocated; i++) {
		// Allocate each of the 40 addresses and NULL it
		char *address = (char *)g_malloc(sizeof(char) * ADDRESS_MAX_LEN);
		if (!address) {
			free_addresses(addresses, i, num_allocated);
			fprintf(stderr, "Error allocating address\n");
			return 1;
		}
		zero((void *)address, ADDRESS_MAX_LEN);
		addresses[i] = address;
	}
	int addr_count = 0;
	key_pair_t *account_key = NULL;
	account_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		free_addresses(addresses, num_allocated, num_allocated);
		return 1;
	}
	if (derive_from_master_to_account(master_key, account_index, account_key) != 0) {
		fprintf(stderr, "Failure deriving account key\n");
		free_addresses(addresses, num_allocated, num_allocated);
		g_free((void *)account_key, sizeof(key_pair_t));
		return 1;
	}
	for (uint32_t change = 0; change < 2; change++) { // 0 for external, 1 for internal
		// Generate the change (chain)
		key_pair_t *change_key = NULL;
		change_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
		if (!change_key) {
			fprintf(stderr, "Error gcry_malloc_secure\n");
			free_addresses(addresses, num_allocated, num_allocated);
			g_free((void *)account_key, sizeof(key_pair_t));
			return 1;
		}
		if (derive_from_account_to_change(account_key, change, change_key) != 0) { // m'/84'/0'/account'/change	
			fprintf(stderr, "Failure deriving child key\n");
			free_addresses(addresses, num_allocated, num_allocated);
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
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
				return 1;
			}
			if (derive_from_change_to_child(change_key, child_index, child_key) != 0) { // m/84'/0'/account'/change/index
				fprintf(stderr, "Failed to derive child key\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return 1;
			}
			if (pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, addresses[addr_count], ADDRESS_MAX_LEN) != 0) {
				fprintf(stderr, "Failed to generate address\n");
				free_addresses(addresses, num_allocated, num_allocated);
				g_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
				return 1;
			}
			addr_count++;
			g_free((void *)child_key, sizeof(key_pair_t));
		}
		g_free((void *)change_key, sizeof(key_pair_t));
	}
	g_free((void *)account_key, sizeof(key_pair_t));
    	long long balance = get_balance((const char **)addresses, addr_count, last_request);
	free_addresses(addresses, num_allocated, num_allocated);
	return balance;		
}

int scan_one_accounts_external_chain(key_pair_t *master_key, uint32_t account_index, time_t *last_request) {
	char **addresses = NULL;
	int addr_count = 0;
	addresses = (char **)g_malloc(GAP_LIMIT * sizeof(char *));
	if (!addresses) {
		fprintf(stderr, "Failed to allocate addresses array\n");
		return -1;
	}
	for (size_t i = 0; i < GAP_LIMIT; i++) {
		// Allocate each of the 40 addresses and NULL it
		char *address = (char *)g_malloc(sizeof(char) * ADDRESS_MAX_LEN);
		if (address == NULL) {
			fprintf(stderr, "Error allocating address\n");
			free_addresses(addresses, i, (size_t)GAP_LIMIT);
			return 1;
		}
		address[0] = '\0';
		addresses[i] = address;
	}

	key_pair_t *child_key = NULL;
	child_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
	if (!child_key) {
		fprintf(stderr, "Failure allocating child key\n");
		free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
		return 1;
	}
	if (derive_from_master_to_account(master_key, account_index, child_key) != 0) {
		fprintf(stderr, "Error deriving child key\n");
		free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
		g_free((void *)child_key, sizeof(key_pair_t));
		return 1;
	}
	if (derive_from_account_to_change(child_key, (uint32_t)0, child_key) != 0) {
		fprintf(stderr, "Error deriving child key\n");
		free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
		g_free((void *)child_key, sizeof(key_pair_t));
		return 1;
	}
	for (uint32_t index = 0; index < (uint32_t)GAP_LIMIT; index++) {
		if (derive_from_change_to_child(child_key, index, child_key) != 0) {
			fprintf(stderr, "Error deriving child key\n");
			free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
			g_free((void *)child_key, sizeof(key_pair_t));
			return 1;
		}
		if (pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, addresses[addr_count], ADDRESS_MAX_LEN) != 0) {
			fprintf(stderr, "Failed to generate address\n");
			free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
			g_free((void *)child_key, sizeof(key_pair_t));
			return 1;
		}
		addr_count++;	
	}
	curl_buffer_t buffer = {0};
	if (init_curl_and_addresses((const char **)addresses, addr_count, &buffer, last_request) != 0) {
		fprintf(stderr, "Failed to initialize curl and addresses\n");
		free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
		g_free((void *)child_key, sizeof(key_pair_t));
		return 1;
	}
	if (parse_json_for_any_transaction(buffer.data) > 0 ) {
		printf("Account %d have previous transactions on the blockchain.\n", (int)account_index);
		free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
		g_free((void *)child_key, sizeof(key_pair_t));
		return 1;	
	}
	free_addresses(addresses, (size_t)GAP_LIMIT, (size_t)GAP_LIMIT);
	g_free((void *)child_key, sizeof(key_pair_t));
	printf("Account %d have no recorded transactions on the blockchain, we recommend using this account instead.\n", (int)account_index);
	return 0;
}


