/* wallet.c */

#include <gcrypt.h>
#include <curl/curl.h>
#include <jansson.h>
#include "test_vectors.h"
#include "wallet.h"

static const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
//static const char *secp256k1_params = "(ecc (p #FFFFFFFFFFFFFFFEFFFFFFFC2F#) (a #0#) (b #7#) (g #79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798# #483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8#) (n #FFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141#) (h #1#))";

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
}

static uint32_t bech32_polymod(const uint8_t *values, size_t len) {
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
//printf("\n");
//print_bytes_as_hex("Original pub key (33 bytes)", pub_key, pub_key_len);
	// Compute SHA256
	uint8_t sha256[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, sha256, pub_key, pub_key_len);
	// Compute RIPEMD160
	uint8_t ripemd160[20];
	gcry_md_hash_buffer(GCRY_MD_RMD160, ripemd160, sha256, 32);
//print_bytes_as_hex("After RIPEMD160 (PubKeyHash) (20 bytes)", ripemd160, 20);
	// Convert PubKeyHash to 5-bit groups
	uint8_t program_values[BECH32_VALUES_MAX];
	size_t program_values_len;
	convert_bits(program_values, &program_values_len, ripemd160, 20, 8, 5, 1);
	if (program_values_len != 32) { // Expected for 20 bytes (160 bits / 5 = 32, no pad)
		fprintf(stderr, "Unexpected program length: %zu\n", program_values_len);
		return 1;
	}
	// Finish creating ScriptPubKey
	// Data values = version (5-bit) + program_values
	uint8_t data_values[BECH32_VALUES_MAX];
	data_values[0] = 0;
	memcpy(data_values + 1, program_values, program_values_len);
	size_t data_values_len = 1 + program_values_len;


	// Add HRP and compute checksum
	const char *hrp = "bc"; // Mainnet, use 'tb' for testnet
	size_t hrp_len = strlen(hrp);
	size_t check_values_len = data_values_len + hrp_len * 2 + 7; // 1 for separator, 6 for '0' padding
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

    	memcpy(check_values + check_len, data_values, data_values_len);
    	check_len += data_values_len;

	// Append six zeros for padding
	memset(check_values + check_len, 0, 6);
	check_len += 6;

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
		fprintf(stderr, "Failure generating compressed public key\n");
		return 1;
	}
	memcpy(master->key_pub_extended, master->key_pub_compressed, PUBKEY_LENGTH);
	memcpy(master->key_pub_extended + PUBKEY_LENGTH, master->chain_code, CHAINCODE_LENGTH);
	master->key_index = 0; // Master is at depth 0
/*
print_bytes_as_hex("Master Priv    ", master->key_priv, PRIVKEY_LENGTH);
print_bytes_as_hex("Chain Code     ", master->chain_code, CHAINCODE_LENGTH);
print_bytes_as_hex("Compressed Pub ", master->key_pub_compressed, PUBKEY_LENGTH);
print_bytes_as_hex("Extended Pub   ", master->key_pub_extended, PUBKEY_LENGTH + CHAINCODE_LENGTH);
*/
	return 0;
}


int derive_child_key(const key_pair_t *parent, uint32_t index, key_pair_t *child) {
	uint8_t data[37]; // For HMAC input, 1 + 32 priv + 4 index or 33 pub + 4 index
	size_t data_len;
	int hardened = (index & HARD_FLAG) != 0; // 0: normal, 0x80000000: hardened
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
	if (gcry_mpi_print(GCRYMPI_FMT_USG, child->key_priv, PRIVKEY_LENGTH, &written, child_priv_mpi) != 0) {
       		gcry_mpi_release(child_priv_mpi);
        	return 1;
    	}
    	gcry_mpi_release(child_priv_mpi);

    	// Generate child public key
    	if (generate_public_key(child->key_priv, child->key_pub_compressed) != 0) {
		fprintf(stderr, "Error generating public key for child\n");
        	return 1;
    	}
	// Update extended keys
    	memcpy(child->key_priv_extended, child->key_priv, PRIVKEY_LENGTH);
    	memcpy(child->key_priv_extended + PRIVKEY_LENGTH, child->chain_code, CHAINCODE_LENGTH);
    	memcpy(child->key_pub_extended, child->key_pub_compressed, PUBKEY_LENGTH);
    	memcpy(child->key_pub_extended + PUBKEY_LENGTH, child->chain_code, CHAINCODE_LENGTH); 
	child->key_index = index & 0xFF;
/*
print_bytes_as_hex("Child Priv Extended    ", child->key_priv_extended, PRIVKEY_LENGTH + CHAINCODE_LENGTH);
print_bytes_as_hex("Child Pub Compressed   ", child->key_pub_compressed, PUBKEY_LENGTH);
print_bytes_as_hex("Child Pub Extended     ", child->key_pub_extended, PUBKEY_LENGTH + CHAINCODE_LENGTH);
*/
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

int derive_from_change_to_child(const key_pair_t *change_key, uint32_t child_index, key_pair_t *child_key) {
//printf("Deriving from change to child\n");
	// Derive from change to child - m/44'/0'/0'/account/change/index
	int result = derive_child_key(change_key, child_index, child_key); // m/44'/0'/account'/change/index
	if (result != 0) {
		fprintf(stderr, "Failed to derive index key\n");
		return -1;
	}
//print_bytes_as_hex("Child key priv", child_key->key_priv, PRIVKEY_LENGTH);
//print_bytes_as_hex("Child key pub", child_key->key_pub_compressed, PUBKEY_LENGTH);
	return 0;
}

int derive_from_account_to_change(const key_pair_t *account_key, uint32_t change_index, key_pair_t *change_key) {
//printf("Deriving from account to change\n");
	// Derive from account to change - m/44'/0'/0'/account/change/
	int result = derive_child_key(account_key, change_index, change_key); // m'/44'/0'/account'/change	
	if (result != 0) {
		fprintf(stderr, "Failure deriving child key\n");
		return -1;
	}
//print_bytes_as_hex("Change key priv", change_key->key_priv, PRIVKEY_LENGTH);
//print_bytes_as_hex("Change key pub", change_key->key_pub_compressed, PUBKEY_LENGTH);
	return 0;
}

// Derive from public key all the way up to account - m/purpose'/coin'/account'/
int derive_from_public_to_account(const key_pair_t *pub_key, uint32_t account_index, key_pair_t *account_key) {
//printf("Deriving from public to account\n");
	// Derive from public to account - m/44'/0'/0'/account
	key_pair_t *purpose_key = NULL;
	purpose_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!purpose_key) {
		fprintf(stderr, "Error gcry malloc for child key\n");
		zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
		return 1;
	}
	int result = derive_child_key(pub_key, HARD_FLAG | 44, purpose_key); // m/44'
	if (result != 0) {
		fprintf(stderr, "Failed to derive purpose key\n");
		zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
		return 1;
	}
//print_bytes_as_hex("Purpose key priv", purpose_key->key_priv, PRIVKEY_LENGTH);
//print_bytes_as_hex("Purpose key pub", purpose_key->key_pub_compressed, PUBKEY_LENGTH);
	key_pair_t *coin_key = NULL;
	coin_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!coin_key) {
		fprintf(stderr, "Error gcry malloc for child key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
		return 1;
	}
	result = derive_child_key(purpose_key, HARD_FLAG | 0, coin_key); // m/44'/0'
	if (result != 0) {
		fprintf(stderr, "Failed to derive coin key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
		return 1;
	}
	
//print_bytes_as_hex("Coin key priv", coin_key->key_priv, PRIVKEY_LENGTH);
//print_bytes_as_hex("Coin key pub", coin_key->key_pub_compressed, PUBKEY_LENGTH);
	result = derive_child_key(coin_key, HARD_FLAG | account_index, account_key); // m/44'/0'/account'
	if (result != 0) {
		fprintf(stderr, "Failed to derive account 0 key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
		return 1;
	}
//print_bytes_as_hex("Account key priv", account_key->key_priv, PRIVKEY_LENGTH);
//print_bytes_as_hex("Account key pub", account_key->key_pub_compressed, PUBKEY_LENGTH);
	zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
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

double get_bitcoin_price(time_t *last_request) {
	CURL *curl = curl_easy_init();
	if (!curl) {
		fprintf(stderr, "Failed to initialize CURL\n");
		return -1.0;
	}
	char url[] = "https://blockchain.info/ticker";
	curl_buffer_t buffer = {0};
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

	time_t now = time(NULL);
	if (*last_request != 0 && difftime(now, *last_request) < 30) {
		int sleep_time = 30 - (int)difftime(now, *last_request);
		printf("Rate limit: 1 request per 30 seconds...\nWaiting %d seconds...\n", sleep_time);
		sleep(sleep_time);
	}
	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
	curl_easy_cleanup(curl);
	if (res != CURLE_OK) {
		fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
		free(buffer.data);
		return -1.0;
	}
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

// Get total balance for a list of addresses (in satoshis)
long long get_balance(const char **addresses, int num_addresses, time_t *last_request) {
	printf("Querying the blockchain for 20 Bech32-P2WPKH addresses (external and internal chain) associated with this wallet account...\n");
	if (*addresses[0] == '\0' || num_addresses == 0) {
		fprintf(stderr, "Addresses invalid.\n");
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
//printf("Addr_List: %s\n", addr_list);
	char url[2048];
	snprintf(url, sizeof(url), "https://blockchain.info/multiaddr?active=%s", addr_list);
	
	// Set the behaviors for the curl handle
	curl_buffer_t buffer = {0};
	curl_easy_setopt(curl, CURLOPT_URL, url);
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_callback_func);
    	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);

	time_t now = time(NULL);
	if (*last_request != 0 && difftime(now, *last_request) < 30) {
		int sleep_time = 30 - (int)difftime(now, *last_request);
		printf("Rate limit: 1 request per 30 seconds...\nWaiting %d seconds...\n", sleep_time);
		sleep(sleep_time);
	}
	// Perform blocking network transfer
    	CURLcode res = curl_easy_perform(curl);
	*last_request = time(NULL);
    	curl_easy_cleanup(curl);

    	if (res != CURLE_OK) {
		fprintf(stderr, "CURL failed: %s\n", curl_easy_strerror(res));
        	free(buffer.data);
        	return -1;
    	}
	// Parse JSON for total balance
	json_error_t error;
	json_t *root = json_loads(buffer.data, 0, &error);
	free(buffer.data);
	if (!root) {
		fprintf(stderr, "JSON parse error: %s\n", error.text);
		return -1;
	}
	long long total_balance = 0;
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

long long get_account_balance(key_pair_t *master_key, uint32_t account_index, time_t *last_request) {
	char **addresses = NULL;
	addresses = gcry_malloc_secure(GAP_LIMIT * 2 * sizeof(char *)); // 42 bytes per address (including comma) * 2 chains
	if (!addresses) {
		fprintf(stderr, "Failed to allocate addresses array\n");
		return -1;
	}
	for (size_t i = 0; i < GAP_LIMIT * 2; i++) {
		// Allocate each of the 200 addresses and NULL it
		char *address = (char *)gcry_malloc_secure(sizeof(char) * ADDRESS_MAX_LEN);
		if (address == NULL) {
			for (int j = 0; j < i; j++) gcry_free(addresses[j]);
			gcry_free(addresses);
			fprintf(stderr, "Error allocating address\n");
			return -1;
		}
		address[0] = '\0';
		addresses[i] = address;
	}
	int addr_count = 0;
	int result;
	key_pair_t *account_key = NULL;
	account_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		for (int j = 0; j < addr_count; j++) gcry_free(addresses[j]);
		gcry_free(addresses);
		return -1;
	}
	result = derive_from_public_to_account(master_key, account_index, account_key); 
	if (result != 0) {
		fprintf(stderr, "Failure deriving account key\n");
		for (int j = 0; j < addr_count; j++) gcry_free(addresses[j]);
		gcry_free(addresses);
		zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
		return -1;
	}
	for (uint32_t change = 0; change < 2; change++) { // 0 for external, 1 for internal
		// Generate the change (chain)
		key_pair_t *change_key = NULL;
		change_key = gcry_malloc_secure(sizeof(key_pair_t));
		if (!change_key) {
			fprintf(stderr, "Error gcry_malloc_secure\n");
			for (int j = 0; j < addr_count; j++) gcry_free(addresses[j]);
			gcry_free(addresses);
			zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
			return -1;
		}
		result = derive_from_account_to_change(account_key, change, change_key); // m'/44'/0'/account'/change	
		if (result != 0) {
			fprintf(stderr, "Failure deriving child key\n");
			for (int j = 0; j < addr_count; j++) gcry_free(addresses[j]);
			gcry_free(addresses);
			zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
			return -1;
		}
		// For each change (chain), go through all the indexes
		for (uint32_t child_index = 0; child_index < (uint32_t) GAP_LIMIT; child_index++) {
			key_pair_t *child_key = NULL;
			child_key = gcry_malloc_secure(sizeof(key_pair_t));
			if (!child_key) {
					fprintf(stderr, "Error gcry_malloc_secure\n");
					for (int k = 0; k < addr_count; k++) gcry_free(addresses[k]);
					gcry_free(addresses);
					zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
					return -1;
				}
				result = derive_from_change_to_child(change_key, child_index, child_key); // m/44'/0'/account'/change/index
				if (result != 0) {
					fprintf(stderr, "Failed to derive child key\n");
					for (int k = 0; k < addr_count; k++) gcry_free(addresses[k]);
					gcry_free(addresses);
					zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
					return -1;
				}
				result = pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, addresses[addr_count], ADDRESS_MAX_LEN);
				if (result != 0) {
					fprintf(stderr, "Failed to generate address\n");
					for (int k = 0; k < addr_count; k++) gcry_free(addresses[k]);
					gcry_free(addresses);
					zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
					return -1;
				}
				addr_count++;
				zero_and_gcry_free((void *)child_key, sizeof(key_pair_t));
			}
			zero_and_gcry_free((void *)change_key, sizeof(key_pair_t));
		}
	zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
/*
printf("All addresses-\n");
for (int i = 0; i < addr_count; i++) {
	printf("%d: %s\n", i + 1, addresses[i]);
}
*/
    	long long balance = get_balance((const char **)addresses, addr_count, last_request);
    	for (int k = 0; k < addr_count; k++) gcry_free(addresses[k]);
    	gcry_free(addresses);
	return balance;		
}


