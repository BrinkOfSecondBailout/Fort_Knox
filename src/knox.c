/* knox.c */

#include "knox.h"
#include "common.h"
#include "wallet.h"
#include "crypt.h"
#include "mnemonic.h"
#include "curl/curl.h"


void zero(void *buf, size_t size) {
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

void print_logo() {
	FILE *logo = fopen("logo.txt", "r");
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), logo)) {
		printf(BLUE"%s", buffer);
		fflush(stdout);
		usleep(100000);
	}
	printf(RESET);
	fclose(logo);
	return;
}

int init_user(User *user) {
	if (!user) return -1;
	zero((void *)user, sizeof(User));
	zero((void *)user->seed, SEED_LENGTH);
	user->master_key = NULL;
	user->child_keys = NULL;
	user->child_keys = gcry_calloc_secure(INITIAL_CHILD_CAPACITY, sizeof(key_pair_t *));
	if (!user->child_keys) {
		zero((void *)user, sizeof(User));
		gcry_free(user);
		user = NULL;
		return 1;
	}
	for (size_t i = 0; i < INITIAL_CHILD_CAPACITY; i++) {
		user->child_keys[i] = NULL;
	}
	user->child_key_count = 0;
	user->child_key_capacity = INITIAL_CHILD_CAPACITY;
	return 0;
}

void free_user(User *user) {
	if (!user) return;
	if (user->master_key) {
		zero((void *)user->master_key, sizeof(key_pair_t));
		gcry_free(user->master_key);
		user->master_key = NULL;
	}
	if (user->child_keys) {
		for (size_t i = 0; i < user->child_key_count; i++) {
			if (user->child_keys[i]) {
				zero((void *)user->child_keys[i], sizeof(key_pair_t));
				gcry_free(user->child_keys[i]);
				user->child_keys[i] = NULL;
			}
		}
		zero((void *)user->child_keys, user->child_key_capacity * sizeof (key_pair_t *));
		gcry_free(user->child_keys);
		user->child_keys = NULL;
	}
	zero((void *)user->seed, SEED_LENGTH);
	user->child_key_count = 0;
	user->child_key_capacity = 0;
	gcry_free(user);
}

void print_commands() {
	fprintf(stdout, "Welcome bitcoiner! What is your command?\n"
	"- new				Create a new bitcoin wallet\n"
	"- recover			Recover your bitcoin wallet with mnemonic words(& passphrase, if set)\n"
	"- balance			Display balance for all addresses in current wallet\n"
	"- receive			Receive bitcoin with a new address\n"
	"- send				Send bitcoin to an address\n"
	"- help				Safety practices, tips, and educational contents\n"
	"- menu				Show all commands\n"
	"- exit				Exit program\n\n");
	return;
}

Command_Handler c_handlers[] = {
	{ (char *)"new", new_handle},
	{ (char *)"recover", recover_handle},
	{ (char *)"balance", balance_handle},
	{ (char *)"receive", receive_handle},
	{ (char *)"send", send_handle},
	{ (char *)"help", help_handle},
	{ (char *)"menu", menu_handle},
	{ (char *)"exit", exit_handle}
};

int32 exit_handle(User *user) {
	printf("Bye now, bitcoiner!\n");
	exit(0);
}

int has_wallet(User *user) {
	if (user->seed[0] != 0) return 1;
	return 0; 
}

int32 new_handle(User *user) {
	char cmd[256];
	if (has_wallet(user)) {
		while (1) {
			printf("You already have a wallet set in this current account.\n"
				"Would you like to generate a new one anyways and overwrite the existing one?\n");
			zero((void *)cmd, sizeof(cmd));
			if (!fgets(cmd, sizeof(cmd), stdin)) {
				fprintf(stderr, "fgets() failure\n");
			}
			cmd[strlen(cmd) - 1] = '\0';
			int i = 0;
			while (cmd[i] != '\0') {
				cmd[i] = tolower((unsigned char)cmd[i]);
				i++;
			}
			if (strcmp(cmd, "exit") == 0) exit_handle(user);
			if ((strcmp(cmd, "yes") != 0) && (strcmp(cmd, "no") != 0)) {
				printf("Invalid answer, must type 'yes' or 'no'.\n");
			} else if (strcmp(cmd, "no") == 0) {
				printf("Got it, we'll keep the existing wallet for now.\n");
				return 1;
			} else if (strcmp(cmd, "yes") == 0) {
				break;
			}
		}
	}
	printf("Generating a standard BIP44 Bitcoin wallet...\n"
		"If this program is running locally, strongly recommended "
		"that you disconnect from the internet for extra security\n");
	char mnemonic[256];
	char passphrase[256];
	int nword;
	while (1) {
		zero((void *)cmd, sizeof(cmd));
		printf("Select your recovery seed words count (12, 15, 18, 21, 24)\n"
			"Note: the higher the number, the larger the entropy AKA more cryptographically secured\n> ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		nword = atoi(cmd);
		if (nword != 12 && nword != 15 && nword != 18 && nword != 21 && nword != 24) {
			fprintf(stderr, "\nPlease select a valid number - only 12, 15, 18, 21, 24 allowed");
		} else {
			break;
		}
	}
	printf("Got it! %d words it is..\n", nword);
	while (1) {
		printf("Would you like to add an additional passphrase on top of the mnemonic seed words for extra security?\nReply 'yes' or 'no'> ");
		zero((void *)cmd, sizeof(cmd));
		zero((void *)passphrase, sizeof(passphrase));
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		int i = 0;
		while (cmd[i] != '\0') {
			cmd[i] = tolower((unsigned char)cmd[i]);
			i++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if ((strcmp(cmd, "yes") != 0) && (strcmp(cmd, "no") != 0)) {
			printf("\nInvalid answer, must type 'yes' or 'no'\n");
		} else if (strcmp(cmd, "yes") == 0) {
			printf("\nGot it! Let's add a passphrase, a few critical details here:\n"
				RED"Remember that funds sent to this wallet will always need this passphrase to be recovered!\n"RESET
				"Think of this passphrase as the %dth word of your mnemonic seed, you MUST have it\n"
				"Enter your passphrase (*case sensitive*) (up to 256 characters):\n"
				"> ", nword + 1);
			if (!fgets(passphrase, sizeof(passphrase), stdin)) {
				fprintf(stderr, "fgets() failure\n");
				}
				passphrase[strlen(passphrase) - 1] = '\0';
				printf("\nPassphrase successfully included..");
				break;
		} else if (strcmp(cmd, "no") == 0) {
			printf("\nGot it! Your passphrase is left blank\n"
				"You will only need to write down your seed words once it's generated\n");
			passphrase[0] = '\0';
			break;
		}
	}			
	int result;
	result = generate_mnemonic(nword, passphrase, mnemonic, 256, user->seed);
	if (result != 0) {
		fprintf(stderr, "Failure generate wallet seed.\n");
		return 1;
	}
	printf("Here is your brand new bitcoin wallet's mnemonic seed words:\n"
		"\n\n"
		GREEN"%s\n"RESET
		"\n\n"
		RED"IMPORTANT:"RESET 
		" Please write these words down very carefully on a piece of paper\n"
		"Do NOT type or save them on any electronic devices\n"
		"I suggest clearing the terminal immediately after writing the words down\n"
		RED"Losing these words or having them stolen = losing all of your bitcoin\n"RESET, mnemonic);
	if (passphrase[0]) {
		printf(RED"ALSO IMPORTANT:"RESET 
		" Those are ONLY the %d mnemonic seed words\n"
		"but since you added a passphrase, (not listed above), you WILL be responsible\n" 
		"for having it if you want access to the funds sent to this wallet.\n"
		RED"If you attempt to recover this wallet with only your seed words and the incorrect or blank passphrase,\n"
		"you will see a completely different wallet, not the one you're about to use to send funds to\n"RESET, nword);
	}	
	if (user->master_key) {
		zero((void *)user->master_key, sizeof(key_pair_t));
		gcry_free(user->master_key);
		user->master_key = NULL;	
	}
	user->master_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!user->master_key) {
		fprintf(stderr, "Failed to allocate master key\n");
		zero((void *)user->seed, SEED_LENGTH);
		return 1;
	}
	zero((void *)user->master_key, sizeof(key_pair_t));
	result = generate_master_key(user->seed, SEED_LENGTH, user->master_key);
	if (result != 0) {
		zero((void *)user->seed, SEED_LENGTH);
		gcry_free(user->master_key);
		user->master_key = NULL;
		fprintf(stderr, "Failure generating master key\n");
		return 1;
	}
	printf("Master key successfully generated.\n");
	return 0;
}

int32 recover_handle(User *user) {
	char passphrase[256];
	char mnemonic[256];
	char cmd[256];
	int nword;
	if (has_wallet(user)) {
		while (1) {
			printf("You already have a wallet set in this account\n"
				"Would you like to recover a new one anyways and overwrite the existing one?\n> ");
			zero((void *)cmd, sizeof(cmd));
			if (!fgets(cmd, sizeof(cmd), stdin)) {
				fprintf(stderr, "fgets() failure\n");
			}
			cmd[strlen(cmd) - 1] = '\0';
			int i = 0;
			while (cmd[i] != '\0') {
				cmd[i] = tolower((unsigned char)cmd[i]);
				i++;
			}
			if (strcmp(cmd, "exit") == 0) exit_handle(user);
			if ((strcmp(cmd, "yes") != 0) && (strcmp(cmd, "no") != 0)) {
				printf("Invalid answer, must type 'yes' or 'no'.\n");
			} else if (strcmp(cmd, "no") == 0) {
				printf("Got it, we'll keep the existing wallet for now.\n");
				return 1;
			} else if (strcmp(cmd, "yes") == 0) {
				break;
			}
		}
	}
	printf("Highly recommended that you turn your internet off for this part\n");
	while (1) {
		printf("How many words are your mnemonic seed phrase?\n"
			"Enter one of these numbers (12, 15, 18, 21, 24)\n"
			"> ");
		zero((void *)cmd, sizeof(cmd));
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		int i = 0;
		while (cmd[i] != '\0') {
			cmd[i] = tolower((unsigned char)cmd[i]);
			i++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		nword = atoi(cmd);
		if (nword != 12 && nword != 15 && nword != 18 && nword != 21 && nword != 24) {
			fprintf(stderr, "\nPlease select a valid number - only 12, 15, 18, 21, 24 allowed");
		} else {
			break;
		}
	}
	while (1) {
		printf("Got it! You have a %d words mnemonic seed phrase.\n"
		"Next, enter your %d words mnemonic seed phrase, each separated by a single space.\n"
		"Example: habit eager gallery cabbage interest vacuum unaware wait invest gap game lab\n> ", nword, nword);
		zero((void *)mnemonic, sizeof(mnemonic));
		if (!fgets(mnemonic, sizeof(mnemonic), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		mnemonic[strlen(mnemonic) - 1] = '\0';
		size_t mnemonic_len = strlen(mnemonic);
		if (mnemonic_len == 0) {
			fprintf(stderr, "Mnemonic seed phrase cannot be blank, type in your %d words again.\n", nword);
		} else {
			int word_count = 0;
			const char *p = mnemonic;
			while (*p) {
				if (*p == ' ') word_count++;
				p++;
			}
			word_count++;
			if (word_count != nword) {
				fprintf(stderr, "Word counts mismatched, expected %d and got %d.\nTry again\n", nword, word_count);
			} else {
				break;
			}
		}
	}
	printf("Got it! Clear your terminal to prevent hackers from potentially screen capturing your seed!\n");
	while (1) {
		printf("Do you have a passphrase to add to the mnemonic seed?\n"
			"Keep in mind a completely different wallet will appear based on whether a passphrase was used or not.\n"
			"Type 'yes' or 'no'\n> ");
		zero((void *)cmd, sizeof(cmd));
		zero((void *)passphrase, sizeof(passphrase));
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		int i = 0;
		while (cmd[i] != '\0') {
			cmd[i] = tolower((unsigned char)cmd[i]);
			i++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if ((strcmp(cmd, "yes") != 0) && (strcmp(cmd, "no") != 0)) {
			printf("\nInvalid answer, must type 'yes' or 'no'\n");
		} else if (strcmp(cmd, "yes") == 0) {
			printf("\nGot it! Let's add a passphrase, a few critical details here:\n"
				RED"Remember that funds sent to this wallet will always need this passphrase to be recovered!\n"RESET
				"Think of this passphrase as the %dth word of your mnemonic seed, you MUST have it\n"
				"Enter your passphrase (*case sensitive*) (up to 256 characters):\n"
				"> ", nword + 1);
			if (!fgets(passphrase, sizeof(passphrase), stdin)) {
				fprintf(stderr, "fgets() failure\n");
			}
			passphrase[strlen(passphrase) - 1] = '\0';
			printf("\nPassphrase successfully included..");
			break;
		} else if (strcmp(cmd, "no") == 0) {
			printf("\nGot it! Your passphrase is left blank\n");
			passphrase[0] = '\0';
			break;
		}
	}
	uint8_t temp_seed[SEED_LENGTH];
	int result = mnemonic_to_seed(mnemonic, passphrase[0] ? passphrase : "", temp_seed);
	if (result != 0) {
		fprintf(stderr, "Failure converting mnemonic to seed\n");
		return 1;
	}
	zero((void *)user->seed, SEED_LENGTH);
	memcpy(user->seed, temp_seed, SEED_LENGTH);
	zero((void *)temp_seed, SEED_LENGTH);
	printf("Wallet successfully recovered.\n");
	if (user->master_key) {
		zero((void *)user->master_key, sizeof(key_pair_t));
		gcry_free(user->master_key);
		user->master_key = NULL;	
	}
	user->master_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!user->master_key) {
		fprintf(stderr, "Failed to allocate master key\n");
		zero((void *)user->seed, SEED_LENGTH);
		return 1;
	}
	zero((void *)user->master_key, sizeof(key_pair_t));
	result = generate_master_key(user->seed, SEED_LENGTH, user->master_key);
	if (result != 0) {
		zero((void *)user->seed, SEED_LENGTH);
		gcry_free(user->master_key);
		user->master_key = NULL;
		fprintf(stderr, "Failure generating master key\n");
		return 1;
	}
	printf("Master key successfully generated.\n");
	return 0;
}

int32 balance_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl_global_cleanup();
	return 0;
}

int32 receive_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
	// Work our way down the path to m/44'/0'/0'/0
	key_pair_t *account_key = NULL;
	account_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry malloc for child key\n");
	}
	int result = derive_child_key(user->master_key, 0x80000000 | 44, account_key); // m/44'
	if (result != 0) {
		fprintf(stderr, "Failed to derive purpose key\n");
		return 1;
	}
	
	key_pair_t *coin_key = NULL;
	coin_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!coin_key) {
		fprintf(stderr, "Error gcry malloc for child key\n");
	}
	result = derive_child_key(account_key, 0x80000000 | 0, coin_key); // m/44'/0'
	if (result != 0) {
		fprintf(stderr, "Failed to derive coin key\n");
		return 1;
	}
	
	key_pair_t *account0_key = NULL;
	account0_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!account0_key) {
		fprintf(stderr, "Error gcry malloc for child key\n");
		return 1;
	}
	result = derive_child_key(coin_key, 0x80000000 | 0, account0_key); // m/44'/0'/0'
	if (result != 0) {
		fprintf(stderr, "Failed to derive account 0 key\n");
		return 1;
	}
	// Generate a new child key at the next available index (external chain: m/44'/0'/0'/0)
	uint32_t i = user->child_key_count;
	key_pair_t *child_key = NULL;
	child_key = gcry_malloc(sizeof(key_pair_t));
	if (!child_key) {
		fprintf(stderr, "Error gcry malloc child key\n");
		return 1;
	}
	result = derive_child_key(account0_key, i, child_key); // m/44'/0'/0'/0/i
	if (result != 0) {
		fprintf(stderr, "Failed to derive child key %d\n", i);
		return 1;
	}
	// Resize child keys dynamic array if needed
	if (user->child_key_count >= user->child_key_capacity) {
		user->child_key_capacity *= 2;
		user->child_keys = gcry_realloc(user->child_keys, 
				user->child_key_capacity * sizeof(key_pair_t *));
		if (!user->child_keys) {
			zero_and_gcry_free((void *)child_key, sizeof(key_pair_t));
			zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
			zero_and_gcry_free((void *)coin_key, sizeof(key_pair_t));
			zero_and_gcry_free((void *)account0_key, sizeof(key_pair_t));
			fprintf(stderr, "Failure to resize child_keys dynamic array.\n");
			return 1;
		}
		for (size_t j = user->child_key_count; j < user->child_key_capacity; j++) {
			user->child_keys[j] = NULL;
		}	
	}
	user->child_keys[user->child_key_count] = child_key;
	user->child_key_count++;
	// Use the last generated child key for receive address
	if (user->child_key_count == 0) {
		zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
		zero_and_gcry_free((void *)coin_key, sizeof(key_pair_t));
		zero_and_gcry_free((void *)account0_key, sizeof(key_pair_t));
		fprintf(stderr, "No child keys available.\n");
		return 1;
	}
	key_pair_t *receive_key = user->child_keys[user->child_key_count - 1];
	char address[ADDRESS_MAX_LEN];
	result = pubkey_to_address(receive_key->key_pub_compressed, PUBKEY_LENGTH, address, ADDRESS_MAX_LEN);
	if (result != 0) {
		zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
		zero_and_gcry_free((void *)coin_key, sizeof(key_pair_t));
		zero_and_gcry_free((void *)account0_key, sizeof(key_pair_t));
		fprintf(stderr, "Failed to generate receive address.\n");
		return 1;
	}
	// Clean up intermediate keys
	zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
	zero_and_gcry_free((void *)coin_key, sizeof(key_pair_t));
	zero_and_gcry_free((void *)account0_key, sizeof(key_pair_t));
	// New receive address
	printf("New receive address: %s\n", address);
	printf("Use this adddress to receive Bitcoin. You can:\n"
		"- Copy and share this address directly.\n"
		"- Generate a QR code by running a tool like 'qrencode' (e.g. 'qrencode -o qrcode.png %s').\n"
		"- Scan the QR code to send funds.\n", address);
	return 0;
}

int32 send_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
	return 0;
}

int32 help_handle(User *user) {
	return 0;
}

int32 menu_handle(User *user) {
	print_commands();
	return 0;
}

Callback get_command(const char *cmd) {
	if (!cmd || !cmd[0]) {
		return NULL;
	}
	static const size_t len = sizeof(c_handlers) / sizeof(c_handlers[0]);
	for (size_t i = 0; i < len; i++) {
		if (c_handlers[i].command_name && strcmp((char *)cmd, (char *)c_handlers[i].command_name) == 0) {
			return c_handlers[i].callback_function;
		}
	}
	return NULL;
}

void main_loop(User *user) {
	char buf[256], cmd[256];
	while (1) {
		zero_multiple(buf, cmd, NULL);	
		printf("> ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		int i = 0;
		while (cmd[i] != '\0') {
			cmd[i] = tolower((unsigned char)cmd[i]);
			i++;
		}
		Callback cb = get_command(cmd);
		if (!cb) {
			printf("Invalid command\n");
			continue;
		}
		cb(user);
	}
}

int main() {
	User *user;
	user = (User *)gcry_malloc(sizeof(User));
	print_logo();
	init_gcrypt();
	int result = init_user(user);
	if (result != 0) {
		fprintf(stderr, "User secured allocation and setup failed.\n");
		return 1;
	}
	print_commands();
	main_loop(user);
	free_user(user);
	return 0;
}
