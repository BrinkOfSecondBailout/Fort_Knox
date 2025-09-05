/* hash.h */

#ifndef HASH_H
#define HASH_H

extern const char *base58_chars;
extern const char *bech32_charset;

void zero(void *, size_t);
void zero_multiple(void *, ...);
void zero_and_gcry_free(void *, size_t);
void zero_and_gcry_free_multiple(size_t, void *, ...);
int decimal_to_int_le(const char *, size_t, int *);
int hex_to_int(const char *, size_t, int *);
void hex_to_bytes(const char *, uint8_t *, size_t);
void resize_convert_hex_to_bytes(const char *, uint8_t *);
void print_bytes_as_hex(const char *, const uint8_t *, size_t);
int bytes_to_hex(const uint8_t *, size_t, char *, size_t);
void print_seed_hashed(const uint8_t *, size_t);
void print_master_priv_key_hashed(const uint8_t *, size_t);
void print_bits(const char *, const uint8_t *, size_t);
void print_5bit_groups(const char *, const uint8_t *, size_t);
void convert_bits(uint8_t *, size_t *, const uint8_t *, size_t, int, int, int);
uint32_t bech32_polymod(const uint8_t *, size_t);
char *base58_encode(const uint8_t *, size_t);
int bech32_decode_char(char);
int bech32_decode(const char *, uint8_t *, size_t *);
int encode_varint(uint64_t, uint8_t *, size_t *);
void encode_uint32_le(uint32_t, uint8_t *);
void encode_uint64_le(uint64_t, uint8_t *);
void double_sha256(const uint8_t *, size_t, uint8_t*);

#endif
