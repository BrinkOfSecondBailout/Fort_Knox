/* test_vectors.c */
#include "mnemonic.h"
#include "common.h"
#include "wallet.h"
#include "crypt.h"
#include "utxo.h"
#include "test_vectors.h"
#include "hash.h"

// BIP-32 test vectors (from Bitcoin wiki)
static const bip32_test_vector_t test_vectors[] = {
    	{ // Test Vector 1
		// Seed
        	"000102030405060708090a0b0c0d0e0f",
        	// Master private key (chain m)
		"e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
        	// Master public key (chain m)
		"0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2",
		// Master chain code
		"873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508",
		// All paths
       		{"m/0'", "m/0'/1", "m/0'/1/2'", "m/0'/1/2'/2", "m/0'/1/2'/2/1000000000"},
        	// Private keys for respective path
		{
	    		"edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
            		"3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
            		"cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
            		"0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
           		"471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8"
        	},
		// Public keys for respective path
		{
			"035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56",
			"03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c",
			"0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2",
			"02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29",
			"022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011"
		},
		// Chain code for respective path
        	{
            		"47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",
            		"2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19",
			"04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f",
            		"cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd",
            		"c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e"
        	}
    	},
    	{ // Test Vector 2
		"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
		"4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e", 
		"03cbcaa9c98c877a26977d00825c956a238e8dddfbd322cce4f74b0b5bd6ace4a7",
		"60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689",
		{ "m/0", "m/0/2147483647'", "m/0/2147483647'/1", "m/0/2147483647'/1/2147483646'", "m/0/2147483647'/1/2147483646'/2"},
		{
			"abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
			"877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
			"704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
			"f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
			"bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23"
		},
		{
			"02fc9e5af0ac8d9b3cecfe2a888e2117ba3d089d8585886c9c826b6b22a98d12ea",
			"03c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b",
			"03a7d1d856deb74c508e05031f9895dab54626251b3806e16b4bd12e781a7df5b9",
			"02d2b36900396c9282fa14628566582f206a5dd0bcc8d5e892611806cafb0301f0",
			"024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c"
		},
		{
			"f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c",
			"be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9",
			"f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb",
			"637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29",
			"9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271"
		}
    	}
};

static int num_test_vectors = sizeof(test_vectors) / sizeof(bip32_test_vector_t);

// Test seed derivation (BIP-39)
int test_seed_derivation(const char *mnemonic, const char *passphrase, const uint8_t *expected_seed) {
	uint8_t computed_seed[64] = {0}; // Initialize empty key_pair_t

    	// Call your mnemonic_to_seed function
    	if (mnemonic_to_seed(mnemonic, passphrase, computed_seed) != 0) {
        	printf("mnemonic_to_seed failed\n");
        	return 1;
    	}
    	// Compare with expected
	int pass = memcmp(computed_seed, expected_seed, 64) == 0;
    	printf("Seed derivation (using mnemonic_to_seed): %s\n", pass ? GREEN"[ PASS ]"RESET : RED"[ FAIL] "RESET);	
       	print_bytes_as_hex("Expect: ", expected_seed, 64);
        print_bytes_as_hex("Result: ", computed_seed, 64);
	printf("\n");
	printf("---------------------------------------------\n");
    	printf("\n");
	return !pass;
}

int run_mnemonic_test() {
	int failures = 0;
 	// Test BIP-39 seed derivation (using known mnemonic from docs) 
	// according to doc, all test cases have "TREZOR" as the passphrase)
    	// Test case 1
	const char *test_mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
    	const char *test_passphrase = "TREZOR";
    	const char *expected_seed_hex = "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607";
    	uint8_t expected_seed[SEED_LENGTH];
	resize_convert_hex_to_bytes(expected_seed_hex, expected_seed);
    	printf("Seed Derivation Test Case 1\n");	
    	failures += test_seed_derivation(test_mnemonic, test_passphrase, expected_seed);
    	// Test case 2
	const char *test_mnemonic2 = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
    	const char *test_passphrase2 = "TREZOR";
    	const char *expected_seed_hex2 = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440";
    	uint8_t expected_seed2[SEED_LENGTH];
    	resize_convert_hex_to_bytes(expected_seed_hex2, expected_seed2);
	printf("Seed Derivation Test Case 2\n");
    	failures += test_seed_derivation(test_mnemonic2, test_passphrase2, expected_seed2);
    	// Test case 3
	const char *test_mnemonic3 = "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold";
    	const char *test_passphrase3 = "TREZOR";
    	const char *expected_seed_hex3 = "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998";
    	uint8_t expected_seed3[SEED_LENGTH];
	resize_convert_hex_to_bytes(expected_seed_hex3, expected_seed3);
    	printf("Seed Derivation Test Case 3\n");
    	failures += test_seed_derivation(test_mnemonic3, test_passphrase3, expected_seed3);
	return failures;
}
   
// Test master key generation
int test_master_key(const uint8_t *seed, size_t seed_len, const uint8_t *expected_priv, const uint8_t *expected_pub, const uint8_t *expected_chain) {
	// Call generate_master_key function
    	key_pair_t master = {0};
    	if (generate_master_key(seed, seed_len, &master) != 0) {
        	printf("generate_master_key failed\n");
        	return 1;
    	}
    	int pass = memcmp(master.key_priv, expected_priv, PRIVKEY_LENGTH) == 0 &&
		   memcmp(master.key_pub_compressed, expected_pub, PUBKEY_LENGTH) == 0 &&
               	   memcmp(master.chain_code, expected_chain, CHAINCODE_LENGTH) == 0;
    	printf("Master key generation (using generate_master_key): %s\n", pass ? GREEN"[ PASS ]"RESET : RED"[ FAIL ]"RESET);
        print_bytes_as_hex("Expected master priv:  ", expected_priv, PRIVKEY_LENGTH);
        print_bytes_as_hex("Got master priv:       ", master.key_priv, PRIVKEY_LENGTH);
	print_bytes_as_hex("Expected master pub:   ", expected_pub, PUBKEY_LENGTH);
	print_bytes_as_hex("Got public pub:        ", master.key_pub_compressed, PUBKEY_LENGTH);
        print_bytes_as_hex("Expected master chain: ", expected_chain, CHAINCODE_LENGTH);
        print_bytes_as_hex("Got master chain:      ", master.chain_code, CHAINCODE_LENGTH);
    	printf("\n");
	printf("---------------------------------------------\n");
    	printf("\n");
	return !pass;
}

// Test child key derivation
int test_child_derivation(const key_pair_t *master, const char *path, const uint8_t *expected_priv, const uint8_t *expected_pub, const uint8_t *expected_chain) {
    	key_pair_t current = *master; // Start from master
    	// Parse path (e.g., "m/0'/1/2'" -> skip 'm/', parse indices with ' for hardened)
    	const char *p = path + 2; // Skip "m/"
    	while (*p) {
        	uint32_t idx = strtoul(p, (char **)&p, 10);
        	int hardened = 0;
		if (*p == '\'') {
            		hardened = 1;
            		p++;
        	}
        	if (hardened) idx |= 0x80000000;
		// Call derive_child_key for the current chain
        	if (derive_child_key(&current, idx, &current) != 0) return 1;
		// Skip '/' and point at beginning index of next chain
        	if (*p == '/') p++;
    	}
    	int pass = memcmp(current.key_priv, expected_priv, PRIVKEY_LENGTH) == 0 &&
		   memcmp(current.key_pub_compressed, expected_pub, PUBKEY_LENGTH) == 0 &&
          	   memcmp(current.chain_code, expected_chain, CHAINCODE_LENGTH) == 0;
    	printf("Child derivation (%s): %s\n", path, pass ? GREEN"[ PASS ]"RESET : RED"[ FAIL ]"RESET);
    	print_bytes_as_hex("Expected child priv:  ", expected_priv, PRIVKEY_LENGTH);
    	print_bytes_as_hex("Got child priv:       ", current.key_priv, PRIVKEY_LENGTH);
	print_bytes_as_hex("Expected child pub:   ", expected_pub, PUBKEY_LENGTH);
	print_bytes_as_hex("Got child pub:        ", current.key_pub_compressed, PUBKEY_LENGTH);   
 	print_bytes_as_hex("Expected child chain: ", expected_chain, CHAINCODE_LENGTH);
    	print_bytes_as_hex("Got child chain:      ", current.chain_code, CHAINCODE_LENGTH);
    	printf("\n");
	printf("---------------------------------------------\n");
	printf("\n");
    	return !pass;
}

int run_master_and_child_test() {
	int failures = 0;
	// Test BIP-32 master and child for each vector
    	for (int v = 0; v < num_test_vectors; v++) {
		printf("Testing Vector %d\n", v + 1);
        	const bip32_test_vector_t *tv = &test_vectors[v];
        	uint8_t seed[SEED_LENGTH];
        	size_t seed_len = strlen(tv->seed_hex) / 2;
		resize_convert_hex_to_bytes(tv->seed_hex, seed);
		uint8_t priv[PRIVKEY_LENGTH];
		resize_convert_hex_to_bytes(tv->master_priv_hex, priv);
		uint8_t pub[PUBKEY_LENGTH];
		resize_convert_hex_to_bytes(tv->master_pub_hex, pub);
		uint8_t chain[CHAINCODE_LENGTH];
		resize_convert_hex_to_bytes(tv->master_chain_hex, chain);
		// Test master key 
		// (important to pass in explicit seed len since seed sizes can vary 
		// and with padding it could produce the wrong rsult if length not specified)
    	 	failures += test_master_key(seed, seed_len, priv, pub, chain);

        	// Test child keys
        	key_pair_t master = {0};
        	// Populate master from test (using test vector's given private keys and chain code)
		uint8_t master_priv[PRIVKEY_LENGTH];
		resize_convert_hex_to_bytes(tv->master_priv_hex, master_priv);
		memcpy(master.key_priv, master_priv, PRIVKEY_LENGTH);
		uint8_t master_pub[PUBKEY_LENGTH];
		resize_convert_hex_to_bytes(tv->master_pub_hex, master_pub);
		memcpy(master.key_pub_compressed, master_pub, PUBKEY_LENGTH);
		uint8_t master_chain[CHAINCODE_LENGTH];
		resize_convert_hex_to_bytes(tv->master_chain_hex, master_chain);
		memcpy(master.chain_code, master_chain, CHAINCODE_LENGTH);
       		
		// Since each path has all the precursor paths attached, we go straight
		// to the last one and it will test all paths leading up to it	
		int last_path_index = (sizeof(tv->paths) / sizeof(tv->paths[0])) - 1; 
		uint8_t child_priv[PRIVKEY_LENGTH];
		resize_convert_hex_to_bytes(tv->child_priv_hex[last_path_index], child_priv);
		uint8_t child_pub[PUBKEY_LENGTH];
		resize_convert_hex_to_bytes(tv->child_pub_hex[last_path_index], child_pub); 
		uint8_t child_chain[CHAINCODE_LENGTH];
		resize_convert_hex_to_bytes(tv->child_chain_hex[last_path_index], child_chain);
            	int failure;
		failure = test_child_derivation(&master, tv->paths[last_path_index], child_priv, child_pub, child_chain);
		failures += failure;
    	}
	return failures;
}

int test_mnemonic_recovery(const char *mnemonic, const char *passphrase, uint8_t *recovered_seed, key_pair_t *recovered_master) {
	int word_count = 0;
	const char *p = mnemonic;
	while (*p) {
		if (*p == ' ') word_count++;
		p++;
	}
	word_count++;
	int result = mnemonic_to_seed(mnemonic, passphrase, recovered_seed);
	if (result != 0) {
		fprintf(stderr, "mnemonic_to_seed() recovery failure\n");
		return 1;
	}
	result = generate_master_key(recovered_seed, SEED_LENGTH, recovered_master);
	if (result != 0) {
		fprintf(stderr, "generate_master_key() recovery failure\n");
	}
	return 0;
}

int test_mnemonic_generation(int nword, char *mnemonic, const char *passphrase, uint8_t *generated_seed, key_pair_t *generated_master) {
	int result = generate_mnemonic(nword, passphrase, mnemonic, 256, generated_seed);
	if (result != 0) {
		fprintf(stderr, "generate_mnemonic() generation failure\n");
		return 1;
	}
	result = generate_master_key(generated_seed, SEED_LENGTH, generated_master);
	if (result != 0) {
		fprintf(stderr, "generate_master_key() generation failure\n");
		return 1;
	}
	//printf("Mnemonic: %s\n", mnemonic);
	return 0;
}

int mnemonic_recovery_test(int nword, const char *passphrase) {
	int failures = 0;
	uint8_t generated_seed[SEED_LENGTH];
	key_pair_t generated_master;
	uint8_t recovered_seed[SEED_LENGTH];
	key_pair_t recovered_master;
	char mnemonic[256];
	failures += test_mnemonic_generation(nword, mnemonic, passphrase, generated_seed, &generated_master);
	failures += test_mnemonic_recovery(mnemonic, passphrase, recovered_seed, &recovered_master);
	int pass = memcmp(generated_seed, recovered_seed, SEED_LENGTH) == 0 &&
		   memcmp(generated_master.key_priv, recovered_master.key_priv, PRIVKEY_LENGTH) == 0;
	
    	printf("\nMnemonic generation and recovery test:\n%s\n", pass ? GREEN"[ PASS ]"RESET : RED"[ FAIL ]"RESET);
    	print_bytes_as_hex("Generated seed:       ", generated_seed, SEED_LENGTH);
    	print_bytes_as_hex("Recovered seed:       ", recovered_seed, SEED_LENGTH);
	print_bytes_as_hex("Generated master key: ", generated_master.key_priv, PRIVKEY_LENGTH);
	print_bytes_as_hex("Recovered master key: ", recovered_master.key_priv, PRIVKEY_LENGTH);   
	printf("\n");
	printf("---------------------------------------------\n");
	printf("\n");
	return !pass;
}

int run_mnemonic_recovery_test() {
	int failures = 0;
	const char *passphrase = "RandomSTUFF";
	failures += mnemonic_recovery_test(24, passphrase);
	passphrase = "Superlongcrazypassphrase";
	failures += mnemonic_recovery_test(18, passphrase);
	passphrase = "";
	failures += mnemonic_recovery_test(21, passphrase);
	passphrase = "HELLOWORLD";
	failures += mnemonic_recovery_test(15, passphrase);
	return failures;
}


int test_pub_to_address(const uint8_t *pub_key, const char *expected_address) {
	char *generated_address = malloc(ADDRESS_MAX_LEN);
	if (pubkey_to_address(pub_key, PUBKEY_LENGTH, generated_address, ADDRESS_MAX_LEN)) {
		fprintf(stderr, "pubkey_to_address() failure\n");
		return 1;
	}
	size_t generated_len = strlen(generated_address);
	size_t expected_len = strlen(expected_address);
	
	int pass = (generated_len == expected_len) && (strncmp((const char *)generated_address, (const char *)expected_address, expected_len) == 0);
	printf("\nPubkey to address test:\n%s\n", pass ? GREEN"[ PASS ]"RESET : RED"[ FAIL ]"RESET);
    	printf("Generated address: %s\n", generated_address);
    	printf("Expected address : %s\n", expected_address);
	printf("\n");
	printf("---------------------------------------------\n");
	printf("\n");
	free(generated_address);
	return !pass;
}

int run_address_generation_test() {
	int failures = 0;
	// Test 1
	const char *pub_hex1 = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
	size_t pub_len1 = strlen(pub_hex1);
	const char *expected_address1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
	uint8_t pub_key1[PUBKEY_LENGTH];
	hex_to_bytes(pub_hex1, pub_key1, pub_len1);
	failures += test_pub_to_address(pub_key1, expected_address1);	
	// Test 2
	const char *pub_hex2 = "03a1af804ac108a8a51782198c2d034b28bf90c8803f5a53f76276fa69a4eae77f";
	size_t pub_len2 = strlen(pub_hex2);
	const char *expected_address2 = "bc1q8zt37uunpakpg8vh0tz06jnj0jz5jddn7ayctz";
	uint8_t pub_key2[PUBKEY_LENGTH];
	hex_to_bytes(pub_hex2, pub_key2, pub_len2);
	failures += test_pub_to_address(pub_key2, expected_address2);
	// Test 3
	const char *pub_hex3 = "028ab5778966637820b9afb737e73d2b8f345ac6d44e724fc9a4ca2f9384e50f49";
	size_t pub_len3 = strlen(pub_hex3);
	const char *expected_address3 = "bc1qd9c39zfs39utcem4xx0gs9gmkjnjgeasrhyq7j";
	uint8_t pub_key3[PUBKEY_LENGTH];
	hex_to_bytes(pub_hex3, pub_key3, pub_len3);
	failures += test_pub_to_address(pub_key3, expected_address3);
	// Test 4
	const char *pub_hex4 = "02001d586501ca904d93853b70036db922a5e9159783c3ff514caa932cb58d6d82";
	size_t pub_len4 = strlen(pub_hex4);
	const char *expected_address4 = "bc1qfaer00d4c7dcvdm38fhzmewyjsr022l3jkze2g";
	uint8_t pub_key4[PUBKEY_LENGTH];
	hex_to_bytes(pub_hex4, pub_key4, pub_len4);
	failures += test_pub_to_address(pub_key4, expected_address4);
	
	return failures;
}

int run_decoder(const char *address, const char *expected_hex) {
	uint8_t script[25];
	size_t script_len;
	if (address_to_scriptpubkey(address, script, &script_len) != 0) {
		fprintf(stderr, "Scriptpubkey conversion failure\n");
		return 1;
	}
	char script_hex[22];
	bytes_to_hex(script, script_len, script_hex, 22);
	int pass = ((strlen(script_hex) == strlen(expected_hex)) && (strncmp(script_hex, expected_hex, strlen(expected_hex)) == 0));
	printf("\nScriptpubkey Convertion Test:\n%s\n", pass ? GREEN"[ PASS ]"RESET : RED"[ FAIL ]"RESET);
	printf("Expected: %s\n", expected_hex);
	printf("Result  : %s\n", script_hex);
	printf("\n");
	printf("---------------------------------------------\n");
	printf("\n");
	return !pass;
}

int run_bech32_decoder() {
	int failures = 0;
	const char *address1 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
	const char *expected_hex1 = "0014751e76e8199196d454941c45d1b3a323f1433bd6";	
	failures += run_decoder(address1, expected_hex1);
	return failures;
}

int run_sign_transaction_test() {
	char *raw_tx_hex = "02000000000101f5ab6a10237e6d002133b93162f0ae22f1646d6a0fa6e77e6d341dffac6b0df10200000000ffffffff02e803000000000000160014aa7c6ca46df982bfae265f1429325e41b6ffe30d7102000000000000160014572e6abcefad78e89be54fc79ae37a5c18e8cda700000000";
	utxo_t *selected = malloc(1 * sizeof(utxo_t)); // 1 input
    if (!selected) {
        fprintf(stderr, "Failed to allocate selected UTXO\n");
        return 1;
    }
    selected[0].vout = 2; // From sample hex
    selected[0].amount = 1825; // Test amount; adjust based on your sample tx
    strncpy(selected[0].address, "bc1qnrcq57vr0uhycpv4yvrhnz2urr334ax2av5aar", ADDRESS_MAX_LEN); // Test address

    // Dummy key
    selected[0].key = gcry_malloc_secure(sizeof(key_pair_t));
    if (!selected[0].key) {
        free(selected);
        fprintf(stderr, "Failed to allocate key\n");
        return 1;
    }
    zero((void *)selected[0].key, sizeof(key_pair_t));
    // Populate with test pubkey (33 bytes)
    hex_to_bytes("03a39f2f31c9b0eb7eb99623b781fc3a105c6062a62a126015a9653b1d1342216a", selected[0].key->key_pub_compressed, PUBKEY_LENGTH);
    hex_to_bytes("2a74d6937281bd8aeaba6910a885f9551bf003340387e7b1fd222ddbcf197b08", selected[0].key->key_priv, PRIVKEY_LENGTH);
    // Populate txid (reverse the hex from sample)
    // Sample TxID hex: f5ab6a10237e6d002133b93162f0ae22f1646d6a0fa6e77e6d341dffac6b0df1
    // Reversed for standard TxID: d10f6bacff1d34 6d7ee7a60f6a6d64f122ae0f6291b3313321006d7e23106aabf5 (parse properly)
    // For test, use a known TxID
    strncpy(selected[0].txid, "f10d6bacff1d346d7ee7a60f6a6d64f122aef06231b93321006d7e23106aabf5", 65);
    int num_selected = 1;	
	if (sign_transaction(&raw_tx_hex, &selected, num_selected) != 0) {
		fprintf(stderr, "Failure with sign_transaction\n");
		free(selected);
		return 1;		
	}
	size_t tx_len = strlen(raw_tx_hex);
	uint8_t tx_data[tx_len]; 
	hex_to_bytes(raw_tx_hex, tx_data, strlen(raw_tx_hex));
	free(selected);
	free(raw_tx_hex);
	return 0;
}

int main() {
	int failures = 0; 
	//failures += run_mnemonic_test();
	//failures += run_master_and_child_test(); 
	//failures += run_mnemonic_recovery_test();
	//failures += run_address_generation_test();
	//failures += run_bech32_decoder();
	failures += run_sign_transaction_test();
    	printf("Total failures: %d\n", failures);
    	return failures > 0 ? 1 : 0;
}

