/* mnemonic.c */

#include "mnemonic.h"
#include "wallet.h"

int generate_mnemonic(int word_count, char *mnemonic, size_t mnemonic_len) {
	const mnemonic_config_t *config = NULL;
	for (size_t i = 0; i < sizeof(configs) / sizeof(configs[0]); i++) {
		if (configs[i].word_count == word_count) {
			config = &configs[i];
			break;
		}
	}
	if (!config) {
		snprintf(mnemonic, mnemonic_len, "Invalid word count, must be 12, 15, 18, 21, or 24");
		return 1;
	}
	init_gcrypt();
	// Generate entropy
	uint8_t entropy[32];
	gcry_randomize(entropy, config->entropy_bytes, GCRY_STRONG_RANDOM);
	// Compute SHA256 checksum
	uint8_t hash[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, hash, entropy, config->entropy_bytes);
	// Append checksum (first checksum_bits of hash)
	int total_bits = config->entropy_bytes * 8 + config->checksum_bits;
	word_count = total_bits / 11;
	uint8_t buffer[33]; // Max 32 bytes entropy + 1 byte checksum
	memcpy(buffer, entropy, config->entropy_bytes);
	
	// Convert to 11-bit groups and map to words
	char *ptr = mnemonic;
	size_t remaining = mnemonic_len;
	for (int i = 0; i < word_count; i++) {
		// Extract 11 bits
		int bit_offset = i * 11;
		int byte_offset = bit_offset / 8;
		int bit_shift = bit_offset % 8;
		uint16_t value = (buffer[byte_offset] << 8 | buffer[byte_offset + 1]) >> (5 + bit_shift);
		value &= 0x7ff; // Mask to 11 bits
		// Map to word
		if (remaining < strlen(wordlist[value]) + 2) {
			snprintf(mnemonic, mnemonic_len, "Buffer too small\n");
			return 1;
		}
		ptr += snprintf(ptr, remaining, "%s ", wordlist[value]);
		remaining -= strlen(wordlist[value]) + 1;
	}
	// Remove trailing spaces
	if (ptr > mnemonic) *(ptr - 1) = '\0'
	return 0
}

int mnemonic_to_seed(const char *mnemonic, key_pair_t *key_pair) {
        // Use PBKDF2 to derive seed (BIP-39)
        gcry_kdf_hd_t kdf;
        if (gcry_kdf_open(&kdf, GCRY_KDF_PBKDF2, GCRY_MD_SHA512) != 0) return 1;
        if (gcry_kdf_setkey(kdf, (const uint8_t *)"mnemonic", strlen("mnemonic")) != 0) return 1;
        uint8_t seed[64];
        if (gcry_kdf_compute(kdf, mnemonic, strlen(mnemonic), NULL, 0, seed, 64) != 0) return 1;
        gcry_kdf_close(kdf);
        // Store in key_pair_t
        memcpy(key_pair->key_priv, seed, PRIVKEY_LENGTH);
        memcpy(key_pair->chain_code, seed + PRIVKEY_LENGTH, CHAINCODE_LENGTH);
        return 0;
}
