/* wallet.c */

#include "wallet.h"
#include <gcrypt.h>
#include <curl/curl.h>

static const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const char *secp256k1_params = "(ecc (p #FFFFFFFFFFFFFFFEFFFFFFFC2F#) (a #0#) (b #7#) (g #79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798# #483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8#) (n #FFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141#) (h #1#))";

int derive_child_key(const key_pair_t *parent, uint32_t index, key_pair_t *child) {
	uint8_t data[37];
	size_t data_len;
	int hardened = (index & 0x80000000) != 0;
	if (hardened) {
		data[0] = 0x00;
		memcpy(data + 1, parent->key_priv, PRIVKEY_LENGTH);
		data_len = 1 + PRIVKEY_LENGTH;
	} else {
		memcpy(data, parent->key_pub_compressed, PUBKEY_LENGTH);
		data_len = PUBKEY_LENGTH;
	}
	// Append index (big-endian)
	data[data_len + 0] = (index >> 24) & 0xFF;
	data[data_len + 1] = (index >> 16) & 0xFF;
	data[data_len + 2] = (index >> 8) & 0xFF;
	data[data_len + 3] = index & 0xFF;
	data_len += 4;
	// Compute HMAC-SHA512
    	uint8_t hmac_output[64];
    	gcry_md_hd_t hmac;
    	if (gcry_md_open(&hmac, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != 0) return 1;
    	gcry_md_setkey(hmac, parent->chain_code, CHAINCODE_LENGTH);
    	gcry_md_write(hmac, data, data_len);
    	memcpy(hmac_output, gcry_md_read(hmac, GCRY_MD_SHA512), 64);
    	gcry_md_close(hmac);

    	// IL = offset (left 32 bytes), child_chain_code = right 32 bytes
    	uint8_t il[PRIVKEY_LENGTH];
    	memcpy(il, hmac_output, PRIVKEY_LENGTH);
    	memcpy(child->chain_code, hmac_output + PRIVKEY_LENGTH, CHAINCODE_LENGTH);

    	// Child private key = parent_private + IL mod n
    	gcry_mpi_t parent_priv_mpi, il_mpi, n_mpi, child_priv_mpi;
    	gcry_mpi_scan(&parent_priv_mpi, GCRYMPI_FMT_USG, parent->key_priv, PRIVKEY_LENGTH, NULL);
    	gcry_mpi_scan(&il_mpi, GCRYMPI_FMT_USG, il, PRIVKEY_LENGTH, NULL);
    	gcry_mpi_scan(&n_mpi, GCRYMPI_FMT_HEX, "FFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0, NULL);
    	child_priv_mpi = gcry_mpi_new(0);
    	gcry_mpi_addm(child_priv_mpi, parent_priv_mpi, il_mpi, n_mpi);
    	gcry_mpi_release(parent_priv_mpi);
    	gcry_mpi_release(il_mpi);
    	gcry_mpi_release(n_mpi);

    	// Export child private key
    	gcry_mpi_print(GCRYMPI_FMT_USG, child->key_priv, PRIVKEY_LENGTH, NULL, child_priv_mpi);
    	gcry_mpi_release(child_priv_mpi);

    	// Child public key: use libgcrypt ECC to compute parent_pub + (IL * G)
    	gcry_sexp_t curve, parent_pub_sexp, g_sexp, il_sexp, offset_point, child_pub_sexp;
    	gcry_sexp_build(&curve, NULL, secp256k1_params);
    	// Assume parent_pub_compressed is uncompressed for sexp; convert if needed
    	// For simplicity, assume we have parent_pub as sexp; implement conversion
	// gcry_sexp_build(&parent_pub_sexp, NULL, "(public-key (ecc (curve secp256k1) (q #parent_pub_uncomp#)))");
    	// gcry_sexp_build(&g_sexp, NULL, "(public-key (ecc (curve secp256k1) (q #04 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8#)))");
    	// gcry_pk_mul(&offset_point, g_sexp, il_sexp);
    	// gcry_pk_add(&child_pub_sexp, parent_pub_sexp, offset_point);
    	// Then extract compressed pubkey from child_pub_sexp

    	// For now, skip full pubkey derivation if not needed; add as per your codebase

    	// Update extended keys
    	memcpy(child->key_priv_extended, child->key_priv, PRIVKEY_LENGTH);
    	memcpy(child->key_priv_extended + PRIVKEY_LENGTH, child->chain_code, CHAINCODE_LENGTH);
    	memcpy(child->key_pub_extended, child->key_pub_compressed, PUBKEY_LENGTH);
    	memcpy(child->key_pub_extended + PUBKEY_LENGTH, child->chain_code, CHAINCODE_LENGTH);
    	child->key_index = index & 0xFF;

    	return 0;
}

char *base58_encode(const uint8_t *data, size_t data_len) {
	// Skip leading 0's
	size_t zeros = 0;
	while (zeros < data_len && data[zeros] == 0) zeros++;

	// Convert to big int
	size_t size = data_len * 138 / 100 + 1; // Approximate
	uint8_t *temp = calloc(size, 1);
	for (size_t j = 0; j < size; j++) {
		carry += temp[j] * 256;
		temp[j] = carry % 58;
		carry /= 58;
	}
	char *result = malloc(size + zeros + 1);
	memset(result, '1', zeros);
	size_t pos = zeros;
	for (int i = size - 1; i >= 0; i--) {
		if (temp[i] != 0 || pos != zeros) {
			result[pos++] = base58_chars[temp[i]];
		}
	}
	result[pos] = '\0';
	free(temp);
	return result;
}

// Generate P2PKH address from compressed public key
int generate_address(const uint8_t *key_pub_compressed, char *address, size_t address_len) {
    	// Hash public key twice
	uint8_t sha256[32];
    	gcry_md_hash_buffer(GCRY_MD_SHA256, sha256, key_pub_compressed, 33);
    	uint8_t ripemd160[20];
    	gcry_md_hash_buffer(GCRY_MD_RMD160, ripemd160, sha256, 32);
	// Add version byte
   	uint8_t versioned[21];
    	versioned[0] = 0x00; // 0x00-Mainnet P2PKH 0x6F-Testnet 
    	memcpy(versioned + 1, ripemd160, 20);
	// Compute checksum
    	uint8_t checksum[32];
    	gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, versioned, 21);
    	gcry_md_hash_buffer(GCRY_MD_SHA256, checksum, checksum, 32);
	// Concatenate everything
    	uint8_t full[25];
    	memcpy(full, versioned, 21);
    	memcpy(full + 21, checksum, 4);
	// Encode
    	char *encoded = base58_encode(full, 25);
    	snprintf(address, address_len, "%s", encoded);
    	free(encoded);
    	return 0;
}

// Matching the parameters prototype of how curl expects their callback function
static size_t curl_write_callback(void *contents, size_t size, size_t nmemb, void *userdata) {
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

// Get total balance for a list of addresses (in satoshis)
long long get_balance(const char **addresses, int num_addresses) {
	// Set a curl handle for the data transfer
	CURL *curl = curl_easy_init();
	if (!curl) return -1;
	// Build pipe-separated address list for API
	char addr_list[1024] = {0};
	for (int i = 0; i < num_addresses; i++) {
		strncat(addr_list, addresses[i], sizeof(addr_list) - strlen(addr_list) - 1);
		if (i < num_addresses - 1) strncat(addr_list, "|", sizeof(addr_list) - strlen(addr_list) - 1);
	}
	char url[2048];
	snprintf(url, sizeof(url), "https://blockchain.info/multiaddr?active=%s", addr_list);
	
	// Set the behaviors for the curl handle
	curl_buffer_t buffer = {0};
	curl_easy_setopt(curl, CURLOPT_URL, url);
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback);
    	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	// Perform blocking network transfer
    	CURLcode res = curl_easy_perform(curl);
    	curl_easy_cleanup(curl);

    	if (res != CURLE_OK) {
        	free(buffer.data);
        	return -1;
    	}
	// Parse JSON for total balance (simplified)
	char *final_balance_str = strstr(buffer.data, "\"final_balance\":");
	if (!final_balance_str) {
		free(buffer.data);
		return -1;
	}
	long long balance = atoll(final_balance_str + 16); // Skip to the number 16 bytes over
	free(buffer.data);
	return balance;
}

long long get_account_balance(key_pair_t *master_key, uint32_t account_index, int num_addresses) {
	char *addresses = malloc(num_addresses * 2 * 35); // 35 bytes per address (including comma) * 2 chains
	addresses[0] = '\0';
	int addr_count = 0;
	// Derive external and internal chain (change=0)
	for (int change = 0; change < 2; change++) { // 0 for external, 1 for internal
		for (int index = 0; index < num_addresses; index++) {
			key_pair_t child = {0};
			// Derive path: m/44'/0'/account'/change/index (hardened at account)
			// Assume derive_child_key supports multi-level derivation; extended as needed
			derive_child_key(master_key, 44 | 0x80000000, &child); // m/44'
			derive_child_key(&child, 0 | 0x80000000, &child); // m/44'/0'
			derive_child_key(&child, account_index | 0x80000000, &child); // m/44'/0'/account'
			derive_child_key(&child, change, &child) // m/44'/0'/account'/change
			derive_child_key(&child, index, &child) // m/44'/0'/account'/change/index

			char address[35];
			generate_address(child.key_pub_compressed, address, sizeof(address);
			if (addr_count > 0) strcat(addresses, ",");
			strcat(addresses, address);
			addr_count++;
		}
	}
	long long balance = get_balance((const char *)&addresses, addr_count);
	free(addresses);
	return balance;
}

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
	for (size_t i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
	}
}


