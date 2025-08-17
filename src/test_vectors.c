/* test_vectors.c */
#include "mnemonic.h"
#include "common.h"
#include "wallet.h"
// BIP-32 test vectors (from Bitcoin wiki)
static const bip32_test_vector_t test_vectors[] = {
    { // Test Vector 1
        "000102030405060708090a0b0c0d0e0f",
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        {"m/0'", "m/0'/1", "m/0'/1/2'", "m/0'/1/2'/2", "m/0'/1/2'/2/1000000000"},
        {
	    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
            "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        },
        {
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
            "04466b9cc8e161e966409ca52986c584f07e9dc081274fc15234ddf5e5a9f07a",
            "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
            "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
        }
    },
   
    { // Test Vector 2
	"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
	"4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", 
	"60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
	{"m/0", "m/0/2147483647'", "m/0/2147483647'/1", "m/0/2147483647'/1/2147483646'", "m/0/2147483647'/1/2147483646'/2"},
	{
		"abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
		"877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
		"704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
		"f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
		"bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
	},
	{
		"f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
		"be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
		"f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
		"637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
		"9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
	}
};

static int num_test_vectors = sizeof(test_vectors) / sizeof(bip32_test_vector_t);

// Helper: Hex to bytes
void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bytes[i]);
    }
}

// Helper: Print hex
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

// Test seed derivation (BIP-39)
int test_seed_derivation(const char *mnemonic, const char *passphrase, const uint8_t *expected_seed) {
	key_pair_t key_pair = {0}; // Initialize empty key_pair_t

    	// Call your mnemonic_to_seed function
    	if (mnemonic_to_seed(mnemonic, passphrase, &key_pair) != 0) {
        	printf("mnemonic_to_seed failed\n");
        	return 1;
    	}

    	// Reconstruct the 64-byte seed from key_pair (key_priv + chain_code)
    	uint8_t computed_seed[64];
    	memcpy(computed_seed, key_pair.key_priv, PRIVKEY_LENGTH);
    	memcpy(computed_seed + PRIVKEY_LENGTH, key_pair.chain_code, CHAINCODE_LENGTH);

    	// Compare with expected
    	int pass = memcmp(computed_seed, expected_seed, 64) == 0;
    	printf("Seed derivation (using mnemonic_to_seed): %s\n", pass ? "PASS" : "FAIL");
    	if (!pass) {
        	print_hex("Expected seed", expected_seed, 64);
        	print_hex("Got seed", computed_seed, 64);
    	}
    	return !pass;
}

// Test master key generation
int test_master_key(const uint8_t *seed, size_t seed_len, const uint8_t *expected_priv, const uint8_t *expected_chain) {
    key_pair_t master = {0};
    uint8_t hmac_output[64];
    gcry_md_hd_t hmac;
    if (gcry_md_open(&hmac, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC) != 0) return 1;
    gcry_md_setkey(hmac, (const uint8_t *)"Bitcoin seed", strlen("Bitcoin seed"));
    gcry_md_write(hmac, seed, seed_len);
    memcpy(hmac_output, gcry_md_read(hmac, GCRY_MD_SHA512), 64);
    gcry_md_close(hmac);

    memcpy(master.key_priv, hmac_output, PRIVKEY_LENGTH);
    memcpy(master.chain_code, hmac_output + PRIVKEY_LENGTH, CHAINCODE_LENGTH);
    memcpy(master.key_priv_extended, hmac_output, PRIVKEY_LENGTH + CHAINCODE_LENGTH);

    uint8_t exp_priv[PRIVKEY_LENGTH], exp_chain[CHAINCODE_LENGTH];
    hex_to_bytes(expected_priv, exp_priv, PRIVKEY_LENGTH);
    hex_to_bytes(expected_chain, exp_chain, CHAINCODE_LENGTH);

    int pass = memcmp(master.key_priv, exp_priv, PRIVKEY_LENGTH) == 0 &&
               memcmp(master.chain_code, exp_chain, CHAINCODE_LENGTH) == 0;
    printf("Master key generation: %s\n", pass ? "PASS" : "FAIL");
    if (!pass) {
        print_hex("Expected master priv", exp_priv, PRIVKEY_LENGTH);
        print_hex("Got master priv", master.key_priv, PRIVKEY_LENGTH);
        print_hex("Expected master chain", exp_chain, CHAINCODE_LENGTH);
        print_hex("Got master chain", master.chain_code, CHAINCODE_LENGTH);
    }
    return !pass;
}

// Test child key derivation
int test_child_derivation(const key_pair_t *master, const char *path, const uint8_t *expected_priv, const uint8_t *expected_chain) {
    key_pair_t current = *master; // Start from master
    // Parse path (e.g., "m/0'/1/2'" -> skip 'm/', parse indices with ' for hardened)
    const char *p = path + 2; // Skip "m/"
    while (*p) {
        int hardened = 0;
        if (*p == '\'') {
            hardened = 1;
            p++;
        }
        uint32_t idx = strtoul(p, (char **)&p, 10);
        if (hardened) idx |= 0x80000000;

        if (derive_child_key(&current, idx, &current) != 0) return 1;
        if (*p == '/') p++;
    }

    uint8_t exp_priv[PRIVKEY_LENGTH], exp_chain[CHAINCODE_LENGTH];
    hex_to_bytes(expected_priv, exp_priv, PRIVKEY_LENGTH);
    hex_to_bytes(expected_chain, exp_chain, CHAINCODE_LENGTH);

    int pass = memcmp(current.key_priv, exp_priv, PRIVKEY_LENGTH) == 0 &&
               memcmp(current.chain_code, exp_chain, CHAINCODE_LENGTH) == 0;
    printf("Child derivation (%s): %s\n", path, pass ? "PASS" : "FAIL");
    if (!pass) {
        print_hex("Expected child priv", exp_priv, PRIVKEY_LENGTH);
        print_hex("Got child priv", current.key_priv, PRIVKEY_LENGTH);
        print_hex("Expected child chain", exp_chain, CHAINCODE_LENGTH);
        print_hex("Got child chain", current.chain_code, CHAINCODE_LENGTH);
    }
    return !pass;
}

int main() {
    int failures = 0;

    // Test BIP-39 seed derivation (use known mnemonic from docs)
    const char *test_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const char *test_passphrase = "";
    const char *expected_seed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"; // From BIP-39 example
    failures += test_seed_derivation(test_mnemonic, test_passphrase, expected_seed);

    // Test BIP-32 master and child for each vector
    for (int v = 0; v < num_test_vectors; v++) {
        const bip32_test_vector_t *tv = &test_vectors[v];
        uint8_t seed[64];
        size_t seed_len = strlen(tv->seed_hex) / 2;
        hex_to_bytes(tv->seed_hex, seed, seed_len);

        // Test master key
        failures += test_master_key(seed, seed_len, tv->master_priv_hex, tv->master_chain_hex);

        // Test child keys
        key_pair_t master = {0};
        // Populate master from test (in production, derive from seed)
        hex_to_bytes(tv->master_priv_hex, master.key_priv, PRIVKEY_LENGTH);
        hex_to_bytes(tv->master_chain_hex, master.chain_code, CHAINCODE_LENGTH);
        // Assume pubkey is derived; for test, focus on priv/chain

        for (int c = 0; tv->paths[c]; c++) {
            failures += test_child_derivation(&master, tv->paths[c], tv->child_priv_hex[c], tv->child_chain[c]);
        }
    }

    printf("Total failures: %d\n", failures);
    return failures > 0 ? 1 : 0;
}

