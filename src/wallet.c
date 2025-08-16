/* wallet.c */

#include "wallet.h"
#include <gcrypt.h>

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
	for (size_t i = 0; i < len; i++) {
		sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
	}
}

/*
generate_master_key()
derive_child_key()
*/



