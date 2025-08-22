/* wallet.c */

#include "wallet.h"
#include <gcrypt.h>
#include <curl/curl.h>
#include "test_vectors.h"

static const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
//static const char *secp256k1_params = "(ecc (p #FFFFFFFFFFFFFFFEFFFFFFFC2F#) (a #0#) (b #7#) (g #79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798# #483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8#) (n #FFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141#) (h #1#))";

/*
// Decompress compressed pub key to MPI x and y (for secp256k1)
static int decompress_pubkey(const uint8_t *comp, gcry_mpi_t *x_out, gcry_mpi_t *y_out, gcry_mpi_t p) {
	uint8_t prefix = comp[0];
	if (prefix != 0x02 && prefix != 0x03) return 1;
	gcry_mpi_t x = gcry_mpi_new(0);
    	gcry_mpi_scan(&x, GCRYMPI_FMT_USG, comp + 1, 32, NULL);

    	gcry_mpi_t alpha = gcry_mpi_new(0);
    	gcry_mpi_t tmp = gcry_mpi_new(0);
    	gcry_mpi_mul(tmp, x, x);
    	gcry_mpi_mul(alpha, tmp, x);
    	gcry_mpi_add_ui(alpha, alpha, 7);
    	gcry_mpi_mod(alpha, alpha, p);

    	gcry_mpi_t p1 = gcry_mpi_new(0);
    	gcry_mpi_add_ui(p1, p, 1);
    	gcry_mpi_rshift(p1, p1, 2); // (p + 1) / 4

    	gcry_mpi_t beta = gcry_mpi_new(0);
    	gcry_mpi_powm(beta, alpha, p1, p);

   	gcry_mpi_t y = gcry_mpi_new(0);
    	if (gcry_mpi_test_bit(beta, 0) == (prefix & 1)) {
        	gcry_mpi_set(y, beta);
    	} else {
        	gcry_mpi_sub(y, p, beta);
    	}

    	*x_out = x;
    	*y_out = y;

    	gcry_mpi_release(tmp);
    	gcry_mpi_release(alpha);
    	gcry_mpi_release(p1);
    	gcry_mpi_release(beta);
    	return 0;
}

// Compress MPI x and y to 33-byte compressed pub key
static int compress_pubkey(gcry_mpi_t x, gcry_mpi_t y, uint8_t *comp_out) {
	uint8_t x_bytes[32];
    	gcry_mpi_print(GCRYMPI_FMT_USG, x_bytes, 32, NULL, x);
    	uint8_t prefix = gcry_mpi_test_bit(y, 0) == 0 ? 0x02 : 0x03;
    	comp_out[0] = prefix;
    	memcpy(comp_out + 1, x_bytes, 32);
    	return 0;
}
*/

// Helper: Hex to bytes
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
  	for (size_t i = 0; i < len; i++) {
        	sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    	}
}

void resize_convert_hex_to_bytes(const char *hex, uint8_t *bytes) {
	size_t hex_halved = strlen(hex) / 2;
	hex_to_bytes(hex, bytes, hex_halved);
}

// Helper: Print hex
void print_bytes_as_hex(const char *label, const uint8_t *data, size_t len) {
    	printf("%s: ", label);
    	for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    	printf("\n");
}

// Print a hash of the seed, for testing purposes
void print_seed_hashed(const uint8_t *seed, size_t len) {
	unsigned char hash[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, hash, seed, len);
	print_bytes_as_hex("Seed (Hashed SHA-256) -", hash, 32);
}

// Print a hash of the master private key, for testing purposes
void print_master_priv_key_hashed(const uint8_t *priv, size_t len) {
	unsigned char hash[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, hash, priv, len);
	print_bytes_as_hex("Master Private Key (Hashed SHA-256) -", hash, 32);
}

// Helper: Print individual bits of a buffer for debugging
void print_bits(const char *label, const uint8_t *buffer, size_t len) {
    if (!label || !buffer) {
        printf("Error: Invalid input to print_bits\n");
        return;
    }
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("Byte %zu: ", i);
        for (int j = 7; j >= 0; j--) { // Print MSB to LSB
            printf("%d", (buffer[i] >> j) & 1);
            if (j > 0) printf(" "); // Space between bits
        }
        printf(" (0x%02x)\n", buffer[i]);
    }
}

static const char *bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Helper: Print 5-bit groups in binary for checksum debugging
void print_5bit_groups(const char *label, const uint8_t *groups, size_t num_groups) {
    printf("%s (%zu groups):\n", label, num_groups);
    for (size_t i = 0; i < num_groups; i++) {
        printf("Group %zu: ", i);
        for (int j = 4; j >= 0; j--) { // Print MSB to LSB for 5 bits
            printf("%d", (groups[i] >> j) & 1);
        }
        printf(" (%u, char '%c')\n", groups[i], bech32_charset[groups[i]]);
    }
}

void convert_bits(uint8_t *out, size_t *outlen, const uint8_t *in, size_t inlen, int inbits, int outbits, int pad) {
	// Convert witness program bytes in to groups of 8 bits then split into groups of 5-bit
//print_bits("convert_bits input", in, inlen);
	uint32_t val = 0;
	int bits = 0;
	size_t idx = 0;
	for (size_t i = 0; i < inlen; i++) {
		val = (val << 8) | in[i];
		bits += 8;
		while (bits >= outbits) {
			bits -= outbits;
			out[idx++] = (val >> bits) & ((1 << outbits) - 1);
		}
	}
	if (pad && bits) {
		out[idx++] = (val << (outbits - bits)) & ((1 << outbits) - 1);
	}
	*outlen = idx;
//printf("\n");
//print_bits("convert_bits output", out, idx);
}

static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
//printf("Size of values: %ld\n", len);
    static const uint32_t gen[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint32_t b = chk >> 25;
        chk = (chk & 0x1ffffff) << 5 ^ values[i];
        for (int j = 0; j < 5; j++) {
            chk ^= ((b >> j) & 1) ? gen[j] : 0;
        }
    }
    return chk;
}
// Convert compressed pub to P2WPKH (Segwit) address
int pubkey_to_address(const uint8_t *pub_key, size_t pub_key_len, char *address, size_t address_len) {
	if (pub_key_len != PUBKEY_LENGTH || !address) return -1;
print_bytes_as_hex("Original pub key (33 bytes)", pub_key, pub_key_len);
	// Compute SHA256
	uint8_t sha256[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, sha256, pub_key, pub_key_len);
print_bytes_as_hex("After SHA256", sha256, 32);
	// Compute RIPEMD160
	uint8_t ripemd160[20];
	gcry_md_hash_buffer(GCRY_MD_RMD160, ripemd160, sha256, 32);
print_bytes_as_hex("After RIPEMD160 (PubKeyHash) (20 bytes)", ripemd160, 20);
	// Successfully created a P2WPKH scriptPubKey (PubKeyHash)
	// Convert PubKeyHash to 5-bit groups
	uint8_t program_values[BECH32_VALUES_MAX];
	size_t program_values_len;
	convert_bits(program_values, &program_values_len, ripemd160, 20, 8, 5, 1);
	if (program_values_len != 32) { // Expected for 20 bytes (160 bits / 5 = 32, no pad)
		fprintf(stderr, "Unexpected program length: %zu\n", program_values_len);
		return 1;
	}
	// Data values = version (5-bit) + program_values
	uint8_t data_values[BECH32_VALUES_MAX];
	data_values[0] = 0;
	memcpy(data_values + 1, program_values, program_values_len);
	size_t data_values_len = 1 + program_values_len;

	// Add HRP and compute checksum
	const char *hrp = "bc"; // Mainnet, use 'tb' for testnet
	size_t hrp_len = strlen(hrp);
	size_t check_values_len = data_values_len + hrp_len * 2 + 1; // 1 for separator
	uint8_t *check_values = gcry_malloc_secure(check_values_len);
	if (!check_values) return 1;
	
	size_t check_len = 0;
	// Append all high bits (top 3 bits) for each character of HRP
	for (size_t i = 0; i < hrp_len; i++) {
		if (check_len >= check_values_len) {
			gcry_free(check_values);
			return 1;
		}
		check_values[check_len++] = hrp[i] >> 5;
	}
	// Append separator
	if (check_len >= check_values_len) {
		gcry_free(check_values);
		return 1;
	}
	check_values[check_len++] = 0;
	// Append all low bits (bottom 5 bits) for each character of HRP
	for (size_t i = 0; i < hrp_len; i++) {
		if (check_len >= check_values_len) {
			gcry_free(check_values);
			return 1;
		}
		check_values[check_len++] = hrp[i] & 31;
	}

//print_5bit_groups("HRP", check_values, 5);
//print_5bit_groups("Data Values", data_values, 33);
    	memcpy(check_values + check_len, data_values, data_values_len);
    	check_len += data_values_len;

	// Append six zeros for padding
	memset(check_values + check_len, 0, 6);
	check_len += 6;

//printf("check_values allocated: %zu bytes, used: %zu bytes\n", check_values_len, check_len);
//print_bytes_as_hex("Check Values", check_values, check_len);
    	// Compute checksum
    	uint32_t polymod = (bech32_polymod(check_values, check_len)) ^ 1;
    	gcry_free(check_values);

    	// Append checksum to data_values
    	for (int i = 0; i < 6; i++) {
        	if (data_values_len >= BECH32_VALUES_MAX) return 1;
        	data_values[data_values_len++] = (polymod >> (5 * (5 - i))) & 31;
    	}
    	// Encode output
    	size_t pos = 0;
    	memcpy(address, hrp, hrp_len);
    	pos += hrp_len;
    	address[pos++] = '1';
    	for (size_t i = 0; i < data_values_len; i++) {
        	if (pos >= address_len - 1) return 1;
        	address[pos++] = bech32_charset[data_values[i]];
    	}
    	address[pos] = '\0';
    	return 0;
}

// Generate compressed pub key from priv key(secp256k1)
int generate_public_key(const uint8_t *priv_key, uint8_t *pub_key_compressed) {
	// Initialize ECC context for secp256k1
    	gcry_ctx_t ctx;
    	if (gcry_mpi_ec_new(&ctx, NULL, "secp256k1") != 0) return 1;

    	// Convert private key to MPI
    	gcry_mpi_t priv_mpi;
    	if (gcry_mpi_scan(&priv_mpi, GCRYMPI_FMT_USG, priv_key, PRIVKEY_LENGTH, NULL) != 0) {
        	gcry_ctx_release(ctx);
        	return 1;
    	}

    	// Get generator point G
    	gcry_mpi_point_t g_point = gcry_mpi_ec_get_point("g", ctx, 0);
    	if (!g_point) {
        	gcry_mpi_release(priv_mpi);
        	gcry_ctx_release(ctx);
        	return 1;
    	}

    	// Compute public key point: pub = priv * G
    	gcry_mpi_point_t pub_point = gcry_mpi_point_new(0);
    	if (!pub_point) {
        	gcry_mpi_point_release(g_point);
        	gcry_mpi_release(priv_mpi);
        	gcry_ctx_release(ctx);
        	return 1;
    	}
    	gcry_mpi_ec_mul(pub_point, priv_mpi, g_point, ctx);

    	// Extract affine coordinates (x, y)
   	gcry_mpi_t x = gcry_mpi_new(0);
    	gcry_mpi_t y = gcry_mpi_new(0);
    	if (gcry_mpi_ec_get_affine(x, y, pub_point, ctx) != 0) {
        	gcry_mpi_release(x);
        	gcry_mpi_release(y);
        	gcry_mpi_point_release(pub_point);
        	gcry_mpi_point_release(g_point);
        	gcry_mpi_release(priv_mpi);
        	gcry_ctx_release(ctx);
        	return 1;
    	}

    	// Compress public key: 0x02/0x03 + x-coordinate
    	uint8_t x_bytes[32];
   	if (gcry_mpi_print(GCRYMPI_FMT_USG, x_bytes, 32, NULL, x) != 0) {
        	gcry_mpi_release(x);
        	gcry_mpi_release(y);
        	gcry_mpi_point_release(pub_point);
        	gcry_mpi_point_release(g_point);
        	gcry_mpi_release(priv_mpi);
        	gcry_ctx_release(ctx);
        	return 1;
    	}

    	pub_key_compressed[0] = gcry_mpi_test_bit(y, 0) == 0 ? 0x02 : 0x03; // Even/odd y
    	memcpy(pub_key_compressed + 1, x_bytes, 32);

    	// Cleanup
    	gcry_mpi_release(x);
    	gcry_mpi_release(y);
    	gcry_mpi_point_release(pub_point);
    	gcry_mpi_point_release(g_point);
    	gcry_mpi_release(priv_mpi);
    	gcry_ctx_release(ctx);
    	return 0;
}

int generate_master_key(const uint8_t *seed, size_t seed_len, key_pair_t *master) {
	if (seed_len < 16 || seed_len > 64) {
		fprintf(stderr, "Invalid seed length\n");
		return 1;
	}
	// Compute HMAC_SHA512
	uint8_t hmac_output[64];
	gcry_md_hd_t hmac;
	if (gcry_md_open(&hmac, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != 0) return 1;
	gcry_md_setkey(hmac, (const uint8_t *)"Bitcoin seed", strlen("Bitcoin seed"));
	gcry_md_write(hmac, (void *)seed, seed_len);
	memcpy(hmac_output, gcry_md_read(hmac, GCRY_MD_SHA512), 64);
	gcry_md_close(hmac);
	
	// Split output: left 32 bytes = master priv key, right 32 bytes = master chain code
	memset(master, 0, sizeof(key_pair_t));
	memcpy(master->key_priv, hmac_output, PRIVKEY_LENGTH);
	memcpy(master->chain_code, hmac_output + PRIVKEY_LENGTH, CHAINCODE_LENGTH);
	// Construct extended private key (xprv payload, without full serialization)
	memcpy(master->key_priv_extended, master->key_priv, PRIVKEY_LENGTH);
	memcpy(master->key_priv_extended + PRIVKEY_LENGTH, master->chain_code, CHAINCODE_LENGTH);
	// Generate master public key
	if (generate_public_key(master->key_priv, master->key_pub_compressed) != 0) {
		return 1;
	}
	memcpy(master->key_pub_extended, master->key_pub_compressed, PUBKEY_LENGTH);
	memcpy(master->key_pub_extended + PUBKEY_LENGTH, master->chain_code, CHAINCODE_LENGTH);
	master->key_index = 0; // Master is at depth 0
	return 0;
}


int derive_child_key(const key_pair_t *parent, uint32_t index, key_pair_t *child) {
//printf("Starting derive_child_key for index: 0x%08x\n", index);	
	uint8_t data[37]; // For HMAC input, 1 + 32 priv + 4 index or 33 pub + 4 index
	size_t data_len;
	int hardened = (index & 0x80000000) != 0; // 0: normal, 0x80000000: hardened
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
	// Set key to the parent chain code
    	gcry_md_setkey(hmac, parent->chain_code, CHAINCODE_LENGTH);
    	gcry_md_write(hmac, data, data_len);
    	memcpy(hmac_output, gcry_md_read(hmac, GCRY_MD_SHA512), 64);
    	gcry_md_close(hmac);
    	// IL = child offset (left 32 bytes) that's used to generate child private key, IR = child_chain_code (right 32 bytes)
    	uint8_t il[PRIVKEY_LENGTH];
    	memcpy(il, hmac_output, PRIVKEY_LENGTH);
	memset(child->chain_code, 0, CHAINCODE_LENGTH);
    	memcpy(child->chain_code, hmac_output + PRIVKEY_LENGTH, CHAINCODE_LENGTH);

	gcry_error_t err;
    	gcry_mpi_t parent_priv_mpi, il_mpi, n_mpi, child_priv_mpi;
	err = gcry_mpi_scan(&parent_priv_mpi, GCRYMPI_FMT_USG, parent->key_priv, PRIVKEY_LENGTH, NULL);
	if (err) {
		fprintf(stderr, "gcry_mpi_scan failure for parent private key: %s\n", gcry_strerror(err));
		return 1;
	}
	err = gcry_mpi_scan(&il_mpi, GCRYMPI_FMT_USG, il, PRIVKEY_LENGTH, NULL);
	if (err) {
		fprintf(stderr, "gcry_mpi_scan failure for IL: %s\n", gcry_strerror(err));
		return 1;
	}
 	err = gcry_mpi_scan(&n_mpi, GCRYMPI_FMT_HEX, N_VALUE_HEX, 0, NULL);
	if (err) { 
		fprintf(stderr, "gcry_mpi_scan failure for n: %s\n", gcry_strerror(err));
		return 1;
	}

    	child_priv_mpi = gcry_mpi_new(0);
	if (!child_priv_mpi) return 1;

	// The calculation for private key (child = parent priv + IL mod n)
    	gcry_mpi_addm(child_priv_mpi, parent_priv_mpi, il_mpi, n_mpi);

    	gcry_mpi_release(parent_priv_mpi);
    	gcry_mpi_release(il_mpi);
    	gcry_mpi_release(n_mpi);

	// Generate child private key
    	size_t written;
	memset(child->key_priv, 0, PRIVKEY_LENGTH);
	if (gcry_mpi_print(GCRYMPI_FMT_USG, child->key_priv, PRIVKEY_LENGTH, &written, child_priv_mpi) != 0) {
       		gcry_mpi_release(child_priv_mpi);
        	return 1;
    	}
    	gcry_mpi_release(child_priv_mpi);

    	// Generate child public key
	memset(child->key_pub_compressed, 0, PUBKEY_LENGTH);
    	if (generate_public_key(child->key_priv, child->key_pub_compressed) != 0) {
        	return 1;
    	}
	// Update extended keys
	memset(child->key_priv_extended, 0, PRIVKEY_LENGTH + CHAINCODE_LENGTH);
    	memcpy(child->key_priv_extended, child->key_priv, PRIVKEY_LENGTH);
    	memcpy(child->key_priv_extended + PRIVKEY_LENGTH, child->chain_code, CHAINCODE_LENGTH);
	memset(child->key_pub_extended, 0, PUBKEY_LENGTH + CHAINCODE_LENGTH);
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
	for (size_t i = 0; i < data_len; i++) {
		int carry = data[i];
		for (size_t j = 0; j < size; j++) {
			carry += temp[j] * 256;
			temp[j] = carry % 58;
			carry /= 58;
		}
	}
	// Encode to chars
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
static size_t curl_write_callback_func(void *contents, size_t size, size_t nmemb, void *userdata) {
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
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
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
			derive_child_key(&child, change, &child); // m/44'/0'/account'/change
			derive_child_key(&child, index, &child); // m/44'/0'/account'/change/index

			char address[35];
			generate_address(child.key_pub_compressed, address, sizeof(address));
			if (addr_count > 0) strcat(addresses, ",");
			strcat(addresses, address);
			addr_count++;
		}
	}
	long long balance = get_balance((const char **)&addresses, addr_count);
	free(addresses);
	return balance;
}


