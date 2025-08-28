/* knox.c */

#include "knox.h"
#include "common.h"
#include "wallet.h"
#include "crypt.h"
#include "mnemonic.h"
#include "utxo.h"
#include "curl/curl.h"

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
	printf(RED"***For educational purposes ONLY***\n"RESET);
	printf("***This is a HOT wallet built by one developer you should not 'trust', as per the bitcoin ethos***\n");
	printf("***Exercise extreme cautions. Only TINY (if any) amounts of sats should be sent to any wallet derived by this app***\n"
		"***Until much further rigorous testings and verifications***\n"
		"***Any funds sent to a wallet address derived from this app could be lost forever***\n");
	printf("\n...and so with that being said...\n\n");
	printf(GREEN"\n'Wake up Neo...'\n"RESET);
	return;
}

int init_user(User *user) {
	if (!user) return 1;
	zero((void *)user, sizeof(User));
	zero((void *)user->seed, SEED_LENGTH);
	user->master_key = NULL;
	user->accounts = NULL;
	user->accounts = gcry_calloc_secure(ACCOUNTS_CAPACITY, sizeof(account_t));
	if (!user->accounts) {
		zero_and_gcry_free((void *)user, sizeof(User));
		return 1;
	}
	zero((void *)user->accounts, ACCOUNTS_CAPACITY * sizeof(account_t));
	user->accounts_count = 0;
	user->accounts_capacity = ACCOUNTS_CAPACITY;
	user->last_api_request = 0;
	user->last_price_cached = 0;
	double price = get_bitcoin_price(&user->last_api_request);
	if (price > 0.0) {
		user->last_price_cached = price;
	}
	user->last_api_request = time(NULL);
	return 0;
}

void free_user(User *user) {
	if (!user) return;
	printf("Cleaning up secured memory...\n");
	if (user->master_key) {
		zero((void *)user->master_key, sizeof(key_pair_t));
		gcry_free(user->master_key);
		user->master_key = NULL;
		printf("User master key cleared...\n");
	}
	if (user->accounts_count > 0) {
		for (size_t i = 0; i < user->accounts_count; i++) {
			zero_and_gcry_free((void *)user->accounts[i], sizeof(account_t));
			user->accounts[i] = NULL;
		}
		printf("User accounts cleared...\n");
	}
	zero((void *)user->seed, SEED_LENGTH);
	user->accounts_count = 0;
	user->accounts_capacity = 0;
	user->last_api_request = 0;
	user->last_price_cached = 0.0;
	gcry_free(user);
	printf("User data successfully cleared...\n");
	return;
}

void increment_account_used_index(account_t *account) {
	account->used_indexes_count++;
	return;
}

account_t *add_account_to_user(User *user, uint32_t account_index) {
	// Check if account index already exists
	for (size_t i = 0; i < user->accounts_count; i++) {
		if (user->accounts[i]->account_index == account_index) {
			printf("Account index %u already exists in session. Success.\n", account_index);
			return user->accounts[i];
		}
	}
	// Resize dynamic array if necessary
	if (user->accounts_count == user->accounts_capacity) {
		fprintf(stderr, "Maximum accounts reached.\n");
		return NULL;
	}
	// Create new account
	account_t *new_account = (account_t *)gcry_malloc_secure(sizeof(account_t));
	new_account->account_index = account_index;
	// Initialize child keys for account
	uint32_t **used_indexes = gcry_calloc_secure(INITIAL_USED_INDEXES_CAPACITY, sizeof(uint32_t*));
	if (!used_indexes) {
		fprintf(stderr, "Failure allocating used indexes pointers\n");
		zero_and_gcry_free((void *)new_account, sizeof(account_t));
		return NULL;
	}
	new_account->used_indexes_count = 0;
	// Add account to user accounts
	user->accounts[user->accounts_count++] = new_account;
	printf("Successfully added new account %u to session for use\n", account_index);
	return new_account;
}	
	
void print_commands() {
	fprintf(stdout, "Welcome bitcoiner! What is your command?\n\n"
	"- price					Most recent bitcoin price\n"
	"- new					Create a new bitcoin wallet\n"
	"- recover				Recover your bitcoin wallet with mnemonic words(& passphrase, if set)\n"
	"- balance				Display balance for all addresses in current wallet\n"
	"- receive				Receive bitcoin with a new address\n"
	"- send					Send bitcoin to an address\n"
	"- help					Safety practices, tips, and educational contents\n"
	"- menu					Show all commands\n"
	"- exit					Exit program\n\n");
	return;
}

Command_Handler c_handlers[] = {
	{ (char *)"price", price_handle},
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
	free_user(user);
	exit(0);
}

int has_wallet(User *user) {
	if (user->seed[0] != 0) return 1;
	return 0; 
}

int32 price_handle(User *user) {
	double price = get_bitcoin_price(&user->last_api_request);
	if (price < 0.0) {
		fprintf(stderr, "Failed to fetch new price data.\n");
		if (user->last_price_cached != 0.0) {
			printf("Here's the most recent bitcoin price: %.2f\n", user->last_price_cached);
		}
		return 1;
	}
	printf("Bitcoin price: %.2f\n", price);	
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
		printf("Select your recovery seed phrase word count (12, 15, 18, 21, 24)\n"
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
			return 1;
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
				"You will only need to write down and remember your seed words once it's generated\n");
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
				return 1;
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
			return 1;
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
	printf("Got it! You have a %d words mnemonic seed phrase.\n", nword);
	printf("Example: habit eager gallery cabbage interest vacuum unaware wait invest gap game lab\n> ");
	while (1) {
		printf("Enter your %d words mnemonic seed phrase, each separated by a single space, like the example above.\n> ", nword);
		zero((void *)mnemonic, sizeof(mnemonic));
		if (!fgets(mnemonic, sizeof(mnemonic), stdin)) {
			fprintf(stderr, "fgets() failure\n");
			return 1;
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
	printf("Got it!\n");
	printf("Do you have a passphrase to add to the mnemonic seed?\n");
	printf("Keep in mind a completely different wallet will appear based on whether a passphrase was used or not.\n");
	while (1) {
		printf("Type 'yes' or 'no'\n> ");
		zero((void *)cmd, sizeof(cmd));
		zero((void *)passphrase, sizeof(passphrase));
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
			return 1;
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
				return 1;
			}
			passphrase[strlen(passphrase) - 1] = '\0';
			printf("\nPassphrase successfully included...\n");
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
	printf("For the purpose of keeping this app simple and less memory/complexity intensive,\n"
		"we will scan up to 20 child key index addresses per account.\n"
		"This means the balance queried will reflect only of your selected account (up to index 20 of each account).\n"
		"Note: if you have funds in a different account index or if one of your address\n"
		"key index is higher than 20 you will not see those funds reflected in this balance.\n"
		"This does not necessarily mean that the funds aren't in your wallet associated with your seed phrase, however.\n");
	char cmd[256];
	uint32_t account_index;
	while(1) {
		printf("Please enter the account number you'd like to see the balance of (between 0 - 100)\n"
			"Keep in mind that on this app, you are limited to only receiving funds on account 0-3,\n"
			"If you use a higher account on a different wallet software, we can scan it here, (up to 20 indexes).\n"
			"> ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Failure reading account number\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		int j = 0;
		while (cmd[j] != '\0') {
			cmd[j] = tolower((unsigned char)cmd[j]);
			j++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if (atoi(cmd) < 0 || atoi(cmd) > 100) {
			fprintf(stderr, "Enter a valid account number between 0 - 100.\n");
		} else {
			account_index = (uint32_t)atoi(cmd);
			break;
		}
	}
	printf("Please wait while we query the blockchain for your balance...(account %u)\n", account_index);
	curl_global_init(CURL_GLOBAL_DEFAULT);
	long long balance = get_account_balance(user->master_key, account_index, (time_t*)&user->last_api_request);
  	if (balance >= 0) {
		printf("Total balance for this wallet, account %u:\n\n"
		"%lld satoshis (%.8f BTC)\n"
		"%.2f dollars (most recent price: $%.2f)\n",
		account_index,
		balance, balance / SATS_PER_BTC, 
		(balance / SATS_PER_BTC) * user->last_price_cached, 
		user->last_price_cached);
    	} else {
		printf("Failed to retrieve balance\n");
	}
	curl_global_cleanup();
	return 0;
}

int32 receive_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
	int result;
	char cmd[256];
	uint32_t account_index;
	printf("What account do you want to use?\n"
		"We recommend using account 0 as per the BIP44 standard, but enter any number you wish between 0 - 3.\n"
		"We try to keep track of your used accounts for you, but you must also be responsible for them yourself\n"
		"Some bitcoiners prefer keeping accounts separate for different purposes,\n"
		"For ex: 0 for checkings, 1 for savings, 2 for donations, etc...\n"
		"To keep this app simple, we limit the number of accounts you can use to 3.\n"
		"Please keep in mind that your account selection must be sequential, starting from 0,\n"
		"This means if you if you try to enter '1' but account '0' has zero transactions, we will alert you\n"
		"that account 0 should be used instead.\n");
	while (1) {
		zero((void*)cmd, sizeof(cmd));
		printf("Enter account number between 0-3 (recommended: 0) > ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets failure\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		int j = 0;
		while (cmd[j] != '\0') {
			cmd[j] = tolower((unsigned char)cmd[j]);
			j++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if (atoi(cmd) > 3) {
			fprintf(stderr, "Maximum account index for this program is 3. Enter a number from 0 to 3.\n");
		} else {
			account_index = (uint32_t)atoi(cmd);
			break;
		}
	}
	if (account_index > 0) {
		printf("Please wait while we query the blockchain to ensure previous accounts have already been used...\n");
		// Ensure all accounts preceding it have been used
		for (uint32_t index = 0; index < account_index; index++) {
			result = scan_one_accounts_external_chain(user->master_key, index, &user->last_api_request);
			if (result < 0) {
				fprintf(stderr, "Error scanning previous accounts\n");
				continue;
			} else if (result == 0) {
				printf("Since account %d is empty, we will use account %d to receive funds.\n", (int)index, (int)index);
				account_index = index;
				break;
			} else {
				continue;
			}
		}	
	}
	account_t *account = add_account_to_user(user, account_index);
	if (!account) {
		fprintf(stderr, "Failure adding account\n");
		return 1;
	}
	// Work our way down the path to m/44'/0'/0'/account
	key_pair_t *account_key;
	account_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!account_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		return 1;
	}
	result = derive_from_public_to_account(user->master_key, account_index, account_key); // m/44'/0'/account'
	if (result != 0) {
		fprintf(stderr, "Failed to derive account key\n");
		zero_and_gcry_free((void *)account_key, sizeof(key_pair_t));
		return 1;
	}
		
	key_pair_t *change_key;
	change_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!change_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		return 1;
	}
	result = derive_from_account_to_change(account_key, (uint32_t)0, change_key);
	if (result != 0) {
		fprintf(stderr, "Failed to derive change key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
		return 1;
	}
	key_pair_t *child_key;
	child_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!child_key) {
		fprintf(stderr, "Error gcry_malloc_secure\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, NULL);
		return 1;
	}
	result = derive_from_change_to_child(change_key, (uint32_t)account->used_indexes_count, child_key);
	if (result != 0) {
		fprintf(stderr, "Failed to derive child key\n");
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)change_key, (void *)child_key, NULL);
		return 1;
	}
	increment_account_used_index(account);
		
	char address[ADDRESS_MAX_LEN];
	result = pubkey_to_address(child_key->key_pub_compressed, PUBKEY_LENGTH, address, ADDRESS_MAX_LEN);
	if (result != 0) {
		zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)child_key, NULL);	
		fprintf(stderr, "Failed to generate receive address.\n");
		return 1;
	}
	// Clean up intermediate keys
	zero_and_gcry_free_multiple(sizeof(key_pair_t), (void *)account_key, (void *)child_key, NULL);	
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
	printf("For the purpose of keeping this app simple and less memory/complexity intensive,\n"
		"we will scan up to 20 child key index addresses per account.\n"
		"This means the UTXOs queried will reflect only of your selected account (up to index 20 of each account).\n"
		"Note: if you have funds in a different account index or if one of your address\n"
		"key index is higher than 20 you will not see those funds reflected in this UTXOs query.\n"
		"This does not necessarily mean that the funds aren't in your wallet associated with your seed phrase, however.\n");
	char cmd[256];
	uint32_t account_index;
	while(1) {
		printf("Please enter the account number you'd like to see the balance of (between 0 - 100)\n> ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Failure reading account number\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		int j = 0;
		while (cmd[j] != '\0') {
			cmd[j] = tolower((unsigned char)cmd[j]);
			j++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if (atoi(cmd) < 0 || atoi(cmd) > 100) {
			fprintf(stderr, "Enter a valid account number between 0 - 100.\n");
		} else {
			account_index = (uint32_t)atoi(cmd);
			break;
		}
	}
	printf("Please wait while we query the blockchain for your UTXOs' balance...(account %u)\n", account_index);
	utxo_t *utxos = NULL;
	int num_utxos = 0;
	long long total_balance = get_utxos(user->master_key, &utxos, &num_utxos, account_index, &user->last_api_request);
	if (total_balance < 0) {
		fprintf(stderr, "Failed to fetch UTXOs.\n");
		return 1;
	}
	printf("Available balance:\n"
		"%lld satoshis (%.8f BTC)\n"
		"%.2f dollars (most recent price: $%.2f)\n",
		total_balance,(double)total_balance / SATS_PER_BTC,
		((double)total_balance / SATS_PER_BTC) * user->last_price_cached, user->last_price_cached);
	if (total_balance == 0) {
		printf("No sats to send.\n");
		return 0;
	}
	char recipient1[ADDRESS_MAX_LEN];
	char recipient2[ADDRESS_MAX_LEN];
	long long amount;
	while (1) {
		printf("Enter recipient address, be sure to verify thoroughly.\n> ");
		zero((void *)recipient1, ADDRESS_MAX_LEN);
		zero((void *)recipient2, ADDRESS_MAX_LEN);
		if (!fgets(recipient1, ADDRESS_MAX_LEN, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
		}
		printf("Enter recipient address again, make sure it matches your first input.\n> ");	
		if (!fgets(recipient2, ADDRESS_MAX_LEN, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
		}
		if (strncmp(recipient1, recipient2, ADDRESS_MAX_LEN) != 0) {
			fprintf(stderr, "Inputs not matching. Try again\n");
			continue;
		} else {
			printf("Got it!\n");
			break;
		}
	}
	while (1) {
		zero((void *)cmd, 256);
		printf("Enter amount you wish to send in satoshis:\n> ");
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
		}
		amount = (long long)atoi(cmd);
		if (amount < (long long) 0 || amount < total_balance) {
			fprintf(stderr, "Invalid amount, must be more than 0 and less than your total balance.\n");
			continue;
		} else {
			printf("Got it!\n");
			break;
		}
	}
	long long regular_rate;
	long long priority_rate;
	long long fee;
	
	if (get_fee_rate(&regular_rate, &priority_rate, &user->last_api_request) != 0) {
		fprintf(stderr, "Fee rate fetch failed.\n");
		return 1;
	}
	printf("Here are the current market fee rates (in satoshis):\n"
		"Regular (per bytes): %lld (%.8f BTC)\n"
		"Priority (per bytes): %lld (%.8f BTC)\n"
		"Regular total fee (estimated for typical transaction of 1 input and 2 outputs):\n"
		"%lld\n"
		"Priority total fee (estimated for typical transaction of 1 input and 2 outputs):\n"
		"%lld\n",
		regular_rate, regular_rate / SATS_PER_BTC,
		priority_rate, priority_rate / SATS_PER_BTC,
		regular_rate * (long long)estimated_transaction_size(1, 2),
		priority_rate * (long long)estimated_transaction_size(1, 2));
	printf("\nHow much would you like to spend on fees?\n"
		"Keep in mind, the higher you spend, the faster your transaction will be added to the next block.\n"
		"If you choose the regular fee rate, confirmation time will be ~1 hour.\n"
		"Or if you choose the priority rate, confirmation time will be ~10 minutes.\n"
		"You can choose a number lower than the regular rate, but that may leave your transaction in limbo for"
		" a long, indefinite, undefined amount of time\n");
	while (1) {
		printf("Enter how much you'd like to pay for miner fees (in satoshis): \n> ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
		}
		fee = (long long)atoi(cmd);
		if (fee < (long long) 0 || fee + amount < total_balance) {
			fprintf(stderr, "Invalid fee chosen, must be above 0 and less than total balance when added with amount to be sent.\n");
			continue;
		} else {
			printf("Got it!\n");	
			break;
		}
	}
	utxo_t *selected = NULL;
	int num_selected = 0;
	long long input_sum = 0;
	int result = select_coins(utxos, num_utxos, amount, fee, &selected, &num_selected, &input_sum);
	if (result != 0) {
		printf("Coin selection failed\n");
		for (int i = 0; i < num_utxos; i++) gcry_free(utxos[i].key);
		if (num_selected > 0) gcry_free(selected);
		gcry_free(utxos);
		return 1;
	}
	long long change = input_sum - amount - fee;
	key_pair_t *change_back_key = NULL;
	change_back_key = gcry_malloc_secure(sizeof(key_pair_t));
	if (!change_back_key) {
		fprintf(stderr, "Change back key allocation failed\n");
		for (int i = 0; i < num_utxos; i++) gcry_free(utxos[i].key);
		if (num_selected > 0) gcry_free(selected);
		gcry_free(utxos);
		return 1;
	}
	if (change > 0) {
		uint32_t change_index = user->accounts[account_index]->used_indexes_count;
		result = derive_from_public_to_account(user->master_key, account_index, change_back_key); 
		if (result != 0) {
			fprintf(stderr, "Child key derivation failed\n");
			for (int i = 0; i < num_utxos; i++) gcry_free(utxos[i].key);
			if (num_selected > 0) gcry_free(selected);
			gcry_free(change_back_key);
			gcry_free(utxos);
			return 1;
		}
		result = derive_from_account_to_change(change_back_key, 1, change_back_key);
		if (result != 0) {
			fprintf(stderr, "Child key derivation failed\n");
			for (int i = 0; i < num_utxos; i++) gcry_free(utxos[i].key);
			if (num_selected > 0) gcry_free(selected);
			gcry_free(change_back_key);
			gcry_free(utxos);
			return 1;
		}
		result = derive_from_change_to_child(change_back_key, change_index, change_back_key);
		if (result != 0) {
			fprintf(stderr, "Child key derivation failed\n");
			for (int i = 0; i < num_utxos; i++) gcry_free(utxos[i].key);
			if (num_selected > 0) gcry_free(selected);
			gcry_free(change_back_key);
			gcry_free(utxos);
			return 1;
		}
		user->accounts[account_index]->used_indexes_count++;
	}	
	char *raw_tx_hex = NULL;
	result = build_transaction(recipient2, amount, selected, num_selected, change_back_key, fee, &raw_tx_hex);
//	sign_transaction();
//	broadcast_transaction();	
		
		
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
