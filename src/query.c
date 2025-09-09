/* query.c */
#include <jansson.h>
#include <curl/curl.h>
#include "query.h"
#include "wallet.h"
#include "hash.h"

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
		printf("Rate limit: 1 request per 20 seconds...\nWaiting %d seconds...\n", sleep_time);
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
        	return -1.0;
    	}
    	// Extract USD price (last)
    	json_t *usd = json_object_get(root, "USD");
    	if (!json_is_object(usd)) {
        	fprintf(stderr, "Failed to find USD object in JSON\n");
        	json_decref(root);
        	return -1.0;
    	}
    	json_t *last = json_object_get(usd, "last");
    	if (!json_is_number(last)) {
        	fprintf(stderr, "Failed to find last price in USD object\n");
        	json_decref(root);
        	return -1.0;
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

int estimated_transaction_size(int num_inputs, int num_outputs) {
	// Non-witness data
	int non_witness = 4 + 2 + 1 + num_inputs * 40 + 1 + num_outputs * 33 + 4;
	// Witness data (discounted by 1/4 for SegWit)
	double witness = num_inputs * 107.0 / 4.0;
	return (int)ceil(non_witness + witness);
}

int get_fee_rate(long long *regular_rate, long long *priority_rate, time_t *last_request) {
	printf("Fetching miners fee rate...\n");
	CURL *curl = NULL;
	int result = init_curl(&curl);
	if (result != 0) return 1;

	char url[] = "https://mempool.space/api/v1/fees/recommended";
	curl_buffer_t buffer = {0};
	
	result = set_curl_run_curl(curl, url, &buffer, last_request);
	if (result != 0) return 1;
	
	json_error_t error;
	json_t *root = json_loads(buffer.data, 0, &error);
	free(buffer.data);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		return -1;
	}
	json_t *priority = json_object_get(root, "fastestFee");
	if (!json_is_integer(priority)) {
		fprintf(stderr, "Unable to find priority fee rate in JSON\n");
		json_decref(root);
		return -1;
	}
	json_t *regular = json_object_get(root, "hourFee");
	if (!json_is_integer(regular)) {
		fprintf(stderr, "Unable to find regular fee rate in JSON\n");
		json_decref(root);
		return -1;
	}
	*regular_rate = (long long)json_integer_value(regular);
	*priority_rate = (long long)json_integer_value(priority);
	json_decref(root);
	return 0;
}

