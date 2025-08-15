/* test_vectors.c */

#include "common.h"
#include "wallet.h"


void print_bytes_as_hex(const char *label, const uint8_t *data, size_t len) {
	printf("%s: ", label);
	for (size_t i = 0; i < len; i++) {
		printf("%02x", data[i];
	}
	printf("\n");
}

// Test a single vector
int test_vector(const char *name, const char *seed_hex, const char *paths[][2], size_t path_count, const char *exp_priv[], const char *exp_chain[]) {
	pritnf("Testing %s\n", name);
	uint8_t seed[128];
	size_t seed_len = strlen(seed_hex) / 2;
	hex_to_bytes(seed_hex, seed, seed_len);
	
	// Generate master keypair
	key_pair_t master = {0};
	if (generate_master_key(seed, seed_len, &master) != 0) {
		printf("Failed to generate master key\n");
		return 1;
	}

	// Test master key
	uint8_t exp_priv_bytes[PRIVKEY_LENGTH], exp_chain_bytes[CHAINCODE_LENGTH];
	hex_to_bytes(exp_priv[0], exp_priv_bytes, PRIVKEY_LENGTH);
	hex_to_bytes(exp_chain[0], exp_chain_bytes, CHAINCODE_LENGTH);
	int pass = memcmp(master.key_priv, exp_priv_bytes, PRIVKEY_LENGTH) == 0 && memcmp(master.chain_code, exp_chain_bytes, CHAINCODE_LENGTH) == 0;
	printf("Master key: %s\n", pass ? "PASS" : "FAIL");
	if (!pass) {
		print_hex("Expected private key", exp_priv_bytes, PRIVKEY_LENGTH);
		print_hex("Got private key", master.key_priv, PRIVKEY_LENGTH);
		print_hex("Expected chain code", exp_chain_bytes, CHAINCODE_LENGTH);
		print_hex("Got chain code", master.chain_code, CHAINCODE_LENGTH);
	}

	// Test child key (simplified, assumes hardened derivation)
	key_pair_t current = master;
	for (size_t i = 0; i < path_count; i++) {
		uint32_t index = atoi(paths[i][1]) | (strstr(paths[i][0], "H") ? 0x80000000 : 0);
		if (derive_child_key(&current, index, &current) != 0) {
			printf("Failed to derive child key at %s\n", paths[i][0]);
			return 1;
		}
		hex_to_bytes(exp_priv[i + 1], exp_priv_bytes, PRIVKEY_LENGTH);
		hex_to_bytes(exp_chain[i + 1], exp_chain_bytes, CHAINCODE_LENGTH);
		pass = memcmp(current.key_priv, exp_priv_bytes, PRIVKEY_LENGTH) == 0 && memcmp(current.chain_code, exp_chain_bytes, CHAINCODE_LENGTH) == 0;
		printf("Child key %s: %s\n", paths[i][0], pass ? "PASS" : "FAIL");
		if (!pass) {
			print_hex("Expected private key", exp_priv_bytes, PRIVKEY_LENGTH);
		    	print_hex("Got private key", current.key_priv, PRIVKEY_LENGTH);
		    	print_hex("Expected chain code", exp_chain_bytes, CHAINCODE_LENGTH);
		    	print_hex("Got chain code", current.chain_code, CHAINCODE_LENGTH);
		}
	}
	return !pass;
}

int run_test() {
	/*
	if (!gcry_check_version("1.8.0")) {
        	fprintf(stderr, "libgcrypt version too old\n");
        	return 1;
    	}
   	gcry_control(GCRYCTL_DISABLE_SECMEM, 0); // For simplicity
    	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	*/


    	// Test Vector 1
    	const char *tv1_paths[][2] = {{"m/0H", "0H"}};
    	const char *tv1_priv[] = {
        	"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        	"edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
    	};
    	const char *tv1_chain[] = {
        	"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
        	"47fdacbd0f1097043b78c63c20c172ef6caa6a07105d1284e0b4e0ea0f2f4f12"
    	};
    	int result = test_vector("Test Vector 1", "000102030405060708090a0b0c0d0e0f", tv1_paths, 1, tv1_priv, tv1_chain);
	
    	// Test Vector 2
    	const char *tv2_paths[][2] = {{"m/0H", "0H"}, {"m/0H/1", "1"}};
    	const char *tv2_priv[] = {
        	"0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
        	"cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
        	"877c779ad9687164e9c2f4f0f5f6a8e8d9275d9cbbde2f3ab3d2d0e7595a3e7f"
    	};
   	const char *tv2_chain[] = {
        	"47fdacbd0f1097043b78c63c20c172ef6caa6a07105d1284e0b4e0ea0f2f4f12",
        	"0f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1",
        	"2a7857631386ba23dacac34180dd1983734e444fdbf7740413e6b7a6d8b7a4a0"
    	};
    	result |= test_vector("Test Vector 2", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", tv2_paths, 2, tv2_priv, tv2_chain);
	
    	// Test Vector 3
    	const char *tv3_paths[][2] = {{"m/0H", "0H"}};
    	const char *tv3_priv[] = {
        	"8f94b3e5df881316d837e954b297415d859f8e2a0dcda3d489a7d0d57d57b56a",
        	"0e6b1b5b5e4b7a4a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1"
    	};
    	const char *tv3_chain[] = {
        	"9452b549be8f97a5e4b7a4a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c",
        	"2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4"
    	};
    	result |= test_vector("Test Vector 3", "4b381541583be4423346c643850da4b320e46a3ae4", tv3_paths, 1, tv3_priv, tv3_chain);
	
    	// Test Vector 4
    	const char *tv4_paths[][2] = {{"m/0H", "0H"}};
    	const char *tv4_priv[] = {
        	"dd048c0f5e5f6e4a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1",
        	"4b381541583be4423346c643850da4b320e46a3ae4c0b7a4a0a8f4b8c4c2e4a1"
    	};
    	const char *tv4_chain[] = {
        	"2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4",
        	"8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1"
    	};
    	result |= test_vector("Test Vector 4", "60499f801b896d83179a4374aeb7822aaeaceaa0", tv4_paths, 1, tv4_priv, tv4_chain);

   	 // Test Vector 5
    	const char *tv5_paths[][2] = {{"m/0H", "0H"}};
    	const char *tv5_priv[] = {
        	"704addf544a06f479b8398b6a63a8a3561b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4",
        	"0f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1"
    	};
    	const char *tv5_chain[] = {
        	"2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4",
        	"8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1b8f5b3c4e8b7a4a0a8f4b8c4c2e4a1b1"
    	};
    	result |= test_vector("Test Vector 5", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6", tv5_paths, 1, tv5_priv, tv5_chain);

    	return result;
}
