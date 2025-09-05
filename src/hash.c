/* hash.c */

#include "crypt.h"
#include "common.h"
#include "hash.h"

const char *base58_chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const char *bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

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

int decimal_to_int_le(const char *decimal, size_t len, int *value) {
	if (!decimal || !value) {
		fprintf(stderr, "Invalid input\n");
		return 1;
	}
	for (int i = 0; i < len; i++) {
        	if (!isdigit(decimal[i])) {
            		fprintf(stderr, "Invalid decimal character: %c\n", decimal[i]);
            		return -1;
        	}
    	}
	char decimal_clean[len + 1];
    	strncpy(decimal_clean, decimal, len);
    	decimal_clean[len] = '\0';
    	int result;
    	if (sscanf(decimal_clean, "%2d", &result) != 1 || result < 0 || result > 99) {
        	fprintf(stderr, "Failed to parse decimal string or out of range: %s\n", decimal_clean);
        	return -1;
    	}
    	*value = result;
	return 0;
}

int hex_to_int(const char *hex, size_t len, int *value) {
	if (!hex || !value) {
		fprintf(stderr, "Invalid input\n");
		return 1;
	} 
	char hex_clean[len + 1];
	for (size_t i = 0; i < len; i++) {
		hex_clean[i] = tolower(hex[0]);
	}
	hex_clean[len] = '\0';
	for (size_t i = 0; i < len; i++) {
        	if (!isxdigit(hex_clean[i])) {
            		fprintf(stderr, "Invalid hex character: %c\n", hex_clean[i]);
            		return -1;
        	}
    	}
	unsigned int result;
    	if (sscanf(hex_clean, "%2x", &result) != 1) {
       		fprintf(stderr, "Failed to parse hex string: %s\n", hex_clean);
        	return -1;
    	}
    	*value = (int)result;
	return 0;
}

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
  	for (size_t i = 0; i < len; i++) {
        	sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    	}
}

void resize_convert_hex_to_bytes(const char *hex, uint8_t *bytes) {
	size_t hex_halved = strlen(hex) / 2;
	hex_to_bytes(hex, bytes, hex_halved);
}

void print_bytes_as_hex(const char *label, const uint8_t *data, size_t len) {
    	printf("%s: ", label);
    	for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    	printf("\n");
}

int bytes_to_hex(const uint8_t *data, size_t len, char *hex, size_t hex_len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02x", data[i]);
    }
    hex[len * 2] = '\0';
    return 0;
}

void print_seed_hashed(const uint8_t *seed, size_t len) {
	unsigned char hash[32];
	gcry_md_hash_buffer(GCRY_MD_SHA256, hash, seed, len);
	print_bytes_as_hex("Seed (Hashed SHA-256) -", hash, 32);
}

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
		val = (val << inbits) | in[i];
		bits += inbits;
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

uint32_t bech32_polymod(const uint8_t *values, size_t len) {
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

int bech32_decode_char(char c) {
	const char *p = strchr(bech32_charset, tolower(c));
	if (p) {
		return p - bech32_charset;
	}
	return -1;
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


int bech32_decode(const char *address, uint8_t *program, size_t *program_len) {
	if (strncmp(address, "bc1q", 4) != 0) {
		fprintf(stderr, "Expecting bc1q for P2WKPH v0 addresses only\n");
		return -1;
	}
	size_t len = strlen(address);
	if (len < 8 || len > 90) {
		fprintf(stderr, "Address must be between 8 and 90 characters\n");
		return -1;
	}
	const char *hrp = "bc";
	size_t hrp_len = strlen(hrp);
	const char *separator = strchr(address, '1');
	if (separator == NULL || separator - address != hrp_len) {
		fprintf(stderr, "No separator\n");
		return -1; // Verify separator is in correct position
	}
	// Decode data part
	uint8_t values[len - hrp_len - 1];
	size_t values_len = 0;
	for (const char *p = separator + 1; *p; p++) {
		int v = bech32_decode_char(*p);
		if (v < 0) return -1;
		values[values_len++] = v;
	}
	// Verify checksum
	if (values_len < 6) return -1; // Checksum is 6 chars
	// Convert to 8 bit bytes
	uint8_t data[values_len * 5 / 8];
	size_t data_len;
	convert_bits(data, &data_len, values + 1, values_len - 6 - 1, 5, 8, 0); // Exclude first byte and exclude checksum
	if (data_len < 2 || data_len > 40) return -1;
	// Program: version + data
	program[0] = 0;
	memcpy(program + 1, data, data_len);
	*program_len = data_len + 1;
	return 0;
}

// Variable length integers
int encode_varint(uint64_t value, uint8_t *buffer, size_t *len) {
	if (value < 0xFD) { // < 253 inputs or outputs
		buffer[0] = (uint8_t)value;
		*len = 1;
	} else if (value <= 0xFFFF) { // 253 to 65535
		buffer[0] = 0xFD;
		buffer[1] = value & 0xFF;
		buffer[2] = (value >> 8) & 0xFF;
		*len = 3;
	} else {
		return 1;
	}
	return 0;
}
// Encode a 32 bit unsigned integer to a 4 byte little endian buffer
void encode_uint32_le(uint32_t value, uint8_t *buffer) {
	buffer[0] = value & 0xFF;
	buffer[1] = (value >> 8) & 0xFF;
	buffer[2] = (value >> 16) & 0xFF;
	buffer[3] = (value >> 24) & 0xFF;
}
// Encode a 64 bit unsigned integer to a 8 byte little endian buffer
void encode_uint64_le(uint64_t value, uint8_t *buffer) {
	for (int i = 0; i < 8; i++) {
		buffer[i] = (value >> (i * 8)) & 0xFF;
	}
}

// Helper: Double SHA256 hash
void double_sha256(const uint8_t *data, size_t len, uint8_t *hash) {
    	gcry_md_hd_t hd;
    	gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    	gcry_md_write(hd, data, len);
    	gcry_md_final(hd);
    	uint8_t temp[32];
    	memcpy(temp, gcry_md_read(hd, GCRY_MD_SHA256), 32);
    	gcry_md_close(hd);
    	gcry_md_open(&hd, GCRY_MD_SHA256, 0);
    	gcry_md_write(hd, temp, 32);
    	gcry_md_final(hd);
    	memcpy(hash, gcry_md_read(hd, GCRY_MD_SHA256), 32);
    	gcry_md_close(hd);
}


