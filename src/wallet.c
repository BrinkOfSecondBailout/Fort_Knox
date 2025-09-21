/* wallet.c */

#include <gcrypt.h>
#include <curl/curl.h>
#include <jansson.h>
#include "test_vectors.h"
#include "wallet.h"
#include "hash.h"
#include "query.h"

int serialize_extended_key(key_pair_t *parent, key_pair_t *extended, int private, char **output) {
	if (!extended) {
		fprintf(stderr, "Invalid inputs\n");
		return 1;
	}
	uint8_t serialized_data[82];
	size_t data_len = 0;
	// Version bytes (mainnet xpriv or xpub)
	uint8_t version[4] = {0x04, 0xb2, private ? 0x43 : 0x47, private ? 0x0c : 0x46 };
	memcpy(serialized_data, version, 4);
	data_len += 4;
	// Depth
	uint8_t depth = extended->depth;
	memcpy(serialized_data + data_len, &depth, 1);
	data_len += 1;
	// Parent fingerprint
	uint8_t parent_fprint[4] = {0}; // Default 0 for master key
	if (parent) {
		// Compute SHA256
		uint8_t sha256[32];
		gcry_md_hash_buffer(GCRY_MD_SHA256, sha256, parent->key_pub_compressed, PUBKEY_LENGTH);
		// Compute RIPEMD160
		uint8_t ripemd160[20];
		gcry_md_hash_buffer(GCRY_MD_RMD160, ripemd160, sha256, 32); 		

		memcpy(parent_fprint, ripemd160, 4);
	}
	memcpy(serialized_data + data_len, parent_fprint, 4);
	data_len += 4;
	// Child index (big-endian)
	uint32_t child_index = extended->key_index;
	serialized_data[data_len + 0] = (child_index >> 24) & 0xFF;
	serialized_data[data_len + 1] = (child_index >> 16) & 0xFF;
	serialized_data[data_len + 2] = (child_index >> 8) & 0xFF;
	serialized_data[data_len + 3] = child_index & 0xFF;
	data_len += 4;
	// Chain code
	memcpy(serialized_data + data_len, extended->chain_code, CHAINCODE_LENGTH);
	data_len += 32;
	// Key (priv with 0x00 prefix, or public)
	uint8_t key[33];
	if (private) {
		key[0] = 0x00;
		memcpy(key + 1, extended->key_priv, PRIVKEY_LENGTH);
	} else {
		memcpy(key, extended->key_pub_compressed, PUBKEY_LENGTH);		
	}
	memcpy(serialized_data + data_len, key, 33);
	data_len += 33;
	// Checksum (first 4 bytes of double SHA256)
	uint8_t hash[32];
	double_sha256(serialized_data, data_len, hash);
	memcpy(serialized_data + data_len, hash, 4);
	data_len += 4;
	// Base58 encode
	*output = base58_encode(serialized_data, data_len);
	if (!output) {
		fprintf(stderr, "Base58 encode failure\n");
		return 1;
	} 	
	return 0;
}

int key_to_pubkeyhash(key_pair_t *key, uint8_t *pubkeyhash) {
	if (!key) {
		fprintf(stderr, "Invalid input\n");
		return 1;
	}
	// SHA256 of compressed public key
    	uint8_t sha256_hash[32];
    	gcry_md_hd_t hd;
    	gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    	gcry_md_write(hd, key->key_pub_compressed, PUBKEY_LENGTH);
    	gcry_md_final(hd);
    	memcpy(sha256_hash, gcry_md_read(hd, GCRY_MD_SHA256), 32);
    	gcry_md_close(hd);
    	// RIPEMD160 of SHA256 hash
    	gcry_md_open(&hd, GCRY_MD_RMD160, 0);
    	gcry_md_write(hd, sha256_hash, 32);
    	gcry_md_final(hd);
    	memcpy(pubkeyhash, gcry_md_read(hd, GCRY_MD_RMD160), 20);
    	gcry_md_close(hd);
    	return 0;
}

int pubkeyhash_to_address(const uint8_t *pub_key_hash, size_t pub_key_hash_len, char *address, size_t address_len) {
	uint8_t program_values[BECH32_VALUES_MAX];
	size_t program_values_len;
	convert_bits(program_values, &program_values_len, pub_key_hash, 20, 8, 5, 1);
	if (program_values_len != 32) { // Expected for 20 bytes (160 bits / 5 = 32, no pad)
		fprintf(stderr, "Unexpected program length: %zu\n", program_values_len);
		return 1;
	}
	// Data values = version (5-bit) + program_values
	uint8_t data_values[BECH32_VALUES_MAX];
	data_values[0] = 0; // OP_0
	memcpy(data_values + 1, program_values, program_values_len);
	size_t data_values_len = 1 + program_values_len;
	// Data values = ScriptPubKey

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

// Convert compressed pub to P2WPKH (Segwit) address
int pubkey_to_address(const uint8_t *pub_key, size_t pub_key_len, char *address, size_t address_len) {
	if (pub_key_len != PUBKEY_LENGTH || !address) return -1;
	// Compute SHA256
	uint8_t sha256[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, sha256, pub_key, pub_key_len);
	// Compute RIPEMD160
	uint8_t ripemd160[20];
	gcry_md_hash_buffer(GCRY_MD_RMD160, ripemd160, sha256, 32); // This is the PubKeyHash aka Witness Program
	// Convert PubKeyHash aka Witness Program to 5-bit groups
	uint8_t program_values[BECH32_VALUES_MAX];
	size_t program_values_len;
	convert_bits(program_values, &program_values_len, ripemd160, 20, 8, 5, 1);
	if (program_values_len != 32) { // Expected for 20 bytes (160 bits / 5 = 32, no pad)
		fprintf(stderr, "Unexpected program length: %zu\n", program_values_len);
		return 1;
	}
	// Data values = version (5-bit) + program_values
	uint8_t data_values[BECH32_VALUES_MAX];
	data_values[0] = 0; // Op_0
	memcpy(data_values + 1, program_values, program_values_len);
	size_t data_values_len = 1 + program_values_len;
	// Data values is the ScriptPubKey

	// Add HRP (human readable part) and compute checksum
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
	master->key_index = (uint32_t)0;
	master->depth = (uint8_t)0; // Master key is at depth 0
	return 0;
}

// This function always requires a parent private key to calculate a child private/public key pair
// Not suitable for a watch-only wallet function where only a parent public key is needed to create a child public key for non-hardened derivation
int derive_child_key(const key_pair_t *parent, uint32_t index, key_pair_t *child) {
	if (!parent || !child) {
		fprintf(stderr, "Invalid inputs in derive_child_key\n");
		return 1;
	}
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
 	err = gcry_mpi_scan(&n_mpi, GCRYMPI_FMT_HEX, CURVE_ORDER, 0, NULL);
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
	child->key_index = index;
	child->depth = (uint8_t)(parent->depth + 1);	
	return 0;
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
	// Derive from change to child - m/84'/0'/0'/account/change/index
	int result = derive_child_key(change_key, child_index, child_key); // m/84'/0'/account'/change/index
	if (result != 0) {
		fprintf(stderr, "Failed to derive index key\n");
		return -1;
	}
	return 0;
}

int derive_from_account_to_change(const key_pair_t *account_key, uint32_t change_index, key_pair_t *change_key) {
	// Derive from account to change - m/84'/0'/0'/account/change/
	int result = derive_child_key(account_key, change_index, change_key); // m'/84'/0'/account'/change	
	if (result != 0) {
		fprintf(stderr, "Failure deriving child key\n");
		return -1;
	}
	return 0;
}

int derive_from_master_to_account(const key_pair_t *master_key, uint32_t account_index, key_pair_t *account_key) {
	// Derive from public to account - m/84'/0'/0'/account
	key_pair_t *purpose_key = NULL;
	purpose_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!purpose_key) {
		fprintf(stderr, "Error gcry malloc for purpose key\n");
		return 1;
	}
	int result = derive_child_key(master_key, HARD_FLAG | 84, purpose_key); // m/84'
	if (result != 0) {
		fprintf(stderr, "Failed to derive purpose key\n");
		zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
		return 1;
	}
	key_pair_t *coin_key = NULL;
	coin_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!coin_key) {
		fprintf(stderr, "Error gcry malloc for coin key\n");
		zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
		return 1;
	}
	result = derive_child_key(purpose_key, HARD_FLAG | 0, coin_key); // m/84'/0'
	if (result != 0) {
		fprintf(stderr, "Failed to derive coin key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
		return 1;
	}
	
	result = derive_child_key(coin_key, HARD_FLAG | account_index, account_key); // m/84'/0'/account'
	if (result != 0) {
		fprintf(stderr, "Failed to derive account 0 key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
		return 1;
	}
	zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)purpose_key, (void *)coin_key, NULL);
	return 0;
} 

int derive_from_master_to_coin(const key_pair_t *master_key, key_pair_t *coin_key) {
	// Derive from public to account - m/84'/0'/0'/account
	key_pair_t *purpose_key = NULL;
	purpose_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!purpose_key) {
		fprintf(stderr, "Error gcry malloc for child key\n");
		return 1;
	}
	int result = derive_child_key(master_key, HARD_FLAG | 84, purpose_key); // m/84'
	if (result != 0) {
		fprintf(stderr, "Failed to derive purpose key\n");
		zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
		return 1;
	}
	result = derive_child_key(purpose_key, HARD_FLAG | 0, coin_key); // m/84'/0'
	if (result != 0) {
		fprintf(stderr, "Failed to derive coin key\n");
		zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
		return 1;
	}
	zero_and_gcry_free((void *)purpose_key, sizeof(key_pair_t));
	return 0;
}

