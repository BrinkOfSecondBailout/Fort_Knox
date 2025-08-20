/* mnemonic.h */

#ifndef MNEMONIC_H
#define MNEMONIC_H

#include "wallet.h"

typedef struct {
        int word_count;
        int entropy_bytes;
        int checksum_bits;
} mnemonic_config_t;

static const mnemonic_config_t configs[] = {
        {12, 16, 4},
        {15, 20, 5},
        {18, 24, 6},
        {21, 28, 7},
        {24, 32, 8}
};

int generate_mnemonic(int, const char *, char *, size_t, uint8_t *);
int mnemonic_to_seed(const char *, const char *, uint8_t *);
#endif
