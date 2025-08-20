/* mnemonic.c */

#include "mnemonic.h"
#include "wallet.h"
#include "bip39_words.h"
#include "crypt.h"

int generate_mnemonic(int word_count, const char *passphrase, char *mnemonic, size_t mnemonic_len, uint8_t *seed_buffer) {
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
	buffer[config->entropy_bytes] = hash[0] >> (8 - config->checksum_bits);	

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
	if (ptr > mnemonic) *(ptr - 1) = '\0';
	return mnemonic_to_seed(mnemonic, passphrase, seed_buffer);
}

int mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_t *seed_buffer) {
        // Use PBKDF2 to derive seed (BIP-39)
        // Prepare salt: "mnemonic" + passphrase (or empty string)
	char salt[128];
	snprintf(salt, sizeof(salt), "mnemonic%s", passphrase[0] ? passphrase : "");
        uint8_t seed[64];
	gcry_error_t err = gcry_kdf_derive(mnemonic, strlen(mnemonic), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, strlen(salt), 2048UL, 64, seed);
	if (err != 0) return 1;
        // Store in key_pair_t
	memcpy((void *)seed_buffer, seed, SEED_LENGTH);
        return 0;
}
