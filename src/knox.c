/* knox.c */

#include "knox.h"
#include "common.h"
#include "wallet.h"
#include "mnemonic.h"
#include "utxo.h"
#include "hash.h"
#include "query.h"
#include "memory.h"
#include "commands.h"

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
	print_red("***For educational purposes ONLY***");
	printf("***This is a HOT wallet built by one developer you should not 'trust', as per the bitcoin ethos***\n");
	printf("***Exercise extreme cautions. Only TINY (if any) amounts of sats should be sent to any wallet derived by this app***\n"
		"***Until much further rigorous testings and verifications***\n"
		"***Any funds sent to a wallet address derived from this app could be lost forever***\n\n"
		"This wallet uses BIP84 derivation path: m/84'/0'/0'/0/0 (Native Segwit P2WPKH),\n"
		"its public addresses will always start with 'bc1q'.\n");

	printf("\n...and so with that being said...\n\n");
	print_green("'Wake up Neo...'");
	return;
}

int init_user(User *user) {
	if (!user) return 1;
	zero((void *)user, sizeof(User));
	user->has_master_key = 0;
	user->accounts = (account_t **)g_calloc(ACCOUNTS_CAPACITY * sizeof(account_t *));
	if (!user->accounts) {
		fprintf(stderr, "Failure allocating accounts\n");
		g_free((void *)user->master_key, sizeof(key_pair_t));
		exit_handle(user);
	}
	user->accounts_count = 0;
	user->accounts_capacity = ACCOUNTS_CAPACITY;
	user->last_api_request = 0;
	user->last_price_cached = 0.0;
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
	if (user->has_master_key) {
		g_free((void *)user->master_key, sizeof(key_pair_t));
		user->master_key = NULL;
		printf("User master key cleared...\n");
	}
	if (user->accounts_count > 0) {
		for (size_t i = 0; i < user->accounts_count; i++) {
			if (user->accounts[i]) {
				g_free((void *)user->accounts[i], sizeof(account_t));
				user->accounts[i] = NULL;
			}
		}
	}
	printf("User accounts cleared...\n");
	if (user->accounts) {
		g_free(user->accounts, ACCOUNTS_CAPACITY * sizeof(account_t **));
		user->accounts = NULL;
	}
	zero((void *)user->seed, SEED_LENGTH);
	user->accounts_count = 0;
	user->accounts_capacity = 0;
	user->last_api_request = 0;
	user->last_price_cached = 0.0;
	g_free((void *)user, sizeof(User));
	printf("User data successfully cleared and free.\n");
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
	if (user->accounts_count == user->accounts_capacity) {
		fprintf(stderr, "Maximum accounts reached.\n");
		printf("Here are the three existing accounts you can use:\n");
		for (int i = 0; i < user->accounts_count; i++) {
			printf("%u\n", user->accounts[i]->account_index);
		}
		return NULL;
	}
	// Create new account
	account_t *new_account = g_malloc(sizeof(account_t));
	if (!new_account) {
		exit_handle(user);
	}
	zero((void *)new_account, sizeof(account_t));
	new_account->account_index = account_index;
	new_account->used_indexes_count = 0;
	// Add account to user accounts
	user->accounts[user->accounts_count++] = new_account;
	printf("Successfully added new account %u to session for use\n", account_index);
	return new_account;
}	
	
void print_menu() {
	fprintf(stdout, "Welcome bitcoiner! What is your command?\n\n"
	"- price					Most recent bitcoin price\n"
	"- new					Create a new bitcoin wallet\n"
	"- recover				Recover your bitcoin wallet with mnemonic words(& passphrase, if set)\n"
	"- key					Serialize your master key (to self-backup), or account key (to import to watch-only wallets)\n"
	"- balance				Display balance for all addresses in current wallet\n"
	"- fee					Fetches the recommended fee rate from mempool.space\n"
	"- receive				Receive bitcoin with a new address\n"
	"- send					Send bitcoin to an address\n"
	"- rbf					Broadcast a new Replace-By-Fee transaction\n" 
	"- help					Safety practices, tips, and educational contents\n"
	"- menu					Show all commands\n"
	"- exit					Exit program\n\n");
	return;
}

Command_Handler c_handlers[] = {
	{ (char *)"price", price_handle},
	{ (char *)"new", new_handle},
	{ (char *)"recover", recover_handle},
	{ (char *)"key", key_handle},
	{ (char *)"balance", balance_handle},
	{ (char *)"fee", fee_handle},
	{ (char *)"receive", receive_handle},
	{ (char *)"send", send_handle},
	{ (char *)"rbf", rbf_handle},
	{ (char *)"help", help_handle},
	{ (char *)"menu", menu_handle},
	{ (char *)"exit", exit_handle}
};

int32 exit_handle(User *user) {
	printf("Bye now, bitcoiner!\n");
	free_user(user);
	free_all();
	exit(0);
}

int has_wallet(User *user) {
	if (user->has_master_key) return 1;
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
	int result;
	if (has_wallet(user)) {
		result = command_loop(cmd, 256, "You already have a wallet set in this current account.\n"
					"Would you like to generate a new one anyways and overwrite?\n"
					"Type 'yes' or 'no'\n", 
					"yes", 
					"no", 
					"Okay, overwriting old wallet.", 
					"Got it, we'll keep existing wallet.");
		if (result < 0) {
			exit_handle(user);
		} else if (result == 1) {
			return 1;
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
	result = command_loop(cmd, 256, "Would you like to add an additional passphrase on top of the mnemonic seed words for extra security?\n"
				"Reply 'yes' or 'no'\n",
				"yes",
				"no",
				"Got it. Let's add a passphrase",
				"Got it. Passphrase is left blank.\n"
				"You will only need to write down your seed word once it's generated.\n");
	if (result < 0) {
		exit_handle(user);
	} else if (result == 0) {
		// Add passphrase
		zero((void *)passphrase, 256);
		print_red("Remember that funds sent to this wallet will always need this passphrase to be recovered!");
		printf("Think of this passphrase as the %dth word of your mnemonic seed, you MUST have it\n"
			"Enter your passphrase (*CASE SENSITIVE*) (up to 256 characters)\n> ", nword + 1);
		if (!fgets(passphrase, 256, stdin)) {
			fprintf(stderr, "Error reading passphrase input\n");
			exit_handle(user);
		}
		passphrase[strlen(passphrase) - 1] = '\0';
		printf("Passphrase added.\n");	
	} else {
		// No passphrase
		zero((void *)passphrase, 256);
		passphrase[0] = '\0';
	}
	zero((void *)mnemonic, 256);	
	result = generate_mnemonic(nword, passphrase, mnemonic, 256, user->seed);
	if (result != 0) {
		fprintf(stderr, "Failure generate wallet seed.\n");
		exit_handle(user);
	}
	printf("Here is your new bitcoin wallet's mnemonic seed words:\n"
		"\n\n"
		GREEN"%s\n"RESET
		"\n\n"
		RED"IMPORTANT:"RESET 
		"Please write those words above very carefully on a piece of paper\n"
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
	if (user->has_master_key) {
		g_free(user->master_key, sizeof(key_pair_t));
		user->master_key = NULL;
		user->has_master_key = 0;
	}
	user->master_key = (key_pair_t *)g_calloc(sizeof(key_pair_t));
	if (!user->master_key) {
		zero((void *)user->seed, SEED_LENGTH);
		fprintf(stderr, "Failed to allocate new master key\n");
		exit_handle(user);
	}
	// Generate master private and public key
	if (generate_master_key(user->seed, SEED_LENGTH, user->master_key) != 0) {
		fprintf(stderr, "Failure generating master key\n");
		zero((void *)user->seed, SEED_LENGTH);
		g_free((void*)user->master_key, sizeof(key_pair_t));
		exit_handle(user);
	}
	user->has_master_key = 1;
	printf("Master key successfully generated.\n");
	return 0;
}

int32 recover_handle(User *user) {
	char passphrase[256];
	char mnemonic[256];
	char cmd[256];
	int nword;
	int result;
	if (has_wallet(user)) {
		result = command_loop(cmd, 256, "You already have a wallet set in this current account.\n"
					"Would you like to generate a new one anyways and overwrite?\n"
					"Type 'yes' or 'no'\n", 
					"yes", 
					"no", 
					"Okay, overwriting old wallet.", 
					"Got it, we'll keep existing wallet.");
		if (result < 0) {
			exit_handle(user);
		} else if (result == 1) {
			return 1;
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
		size_t i = 0;
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
			exit_handle(user);
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
	result = command_loop(cmd, 256, "Type 'yes' or 'no'", "yes", "no", 
				"Got it. Let's add a passphrase.", 
				"Got it. Passphrase will be left blank.");
	if (result < 0) {
		exit_handle(user);
	} else if (result == 0) {
		zero((void *)passphrase, 256);
		print_red("Remember that funds sent to this wallet will always need this passphrase to be recovered!");
		printf("Think of this passphrase as the %dth word of your mnemonic seed, you MUST have it\n"
			"Enter your passphrase (*CASE SENSITIVE*) (up to 256 characters)\n> ", nword + 1);
		if (!fgets(passphrase, 256, stdin)) {
			fprintf(stderr, "Error reading passphrase input\n");
			exit_handle(user);
		}
		passphrase[strlen(passphrase) - 1] = '\0';
		printf("Passphrase added.\n");	
	} else {
		// No passphrase
		zero((void *)passphrase, 256);
		passphrase[0] = '\0';
	}
	uint8_t temp_seed[SEED_LENGTH];
	if (mnemonic_to_seed(mnemonic, passphrase[0] ? passphrase : "", temp_seed) != 0) {
		fprintf(stderr, "Failure converting mnemonic to seed\n");
		exit_handle(user);
	}
	zero((void *)user->seed, SEED_LENGTH);
	memcpy(user->seed, temp_seed, SEED_LENGTH);
	zero((void *)temp_seed, SEED_LENGTH);
	printf("Wallet recovery success.\n");
	if (user->has_master_key) {
		g_free((void *)user->master_key, sizeof(key_pair_t));
		user->master_key = NULL;	
		user->has_master_key = 0;
	}
	user->master_key = (key_pair_t *)g_calloc(sizeof(key_pair_t));
	if (!user->master_key) {
		fprintf(stderr, "Failed to allocate master key\n");
		zero((void *)user->seed, SEED_LENGTH);
		exit_handle(user);
	}
	if (generate_master_key(user->seed, SEED_LENGTH, user->master_key) != 0) {
		fprintf(stderr, "Failure generating master key\n");
		zero((void *)user->seed, SEED_LENGTH);
		g_free((void *)user->master_key, sizeof(key_pair_t));
		exit_handle(user);
	}
	user->has_master_key = 1;
	printf("Master key successfully generated.\n");
	return 0;
}

int32 key_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
	printf("This function allows you to serialize your key in an easier-to-read format.\n"
		"You can choose either your 'master' private key to serialize for backup (this does not substitute as your mnemnonic seed),\n"
		"or your 'account' public key (to import into a watch-only wallet)\n");
	char cmd[256];
	while (1) {	
		printf("Type 'master' or 'account' for the key you want > ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Failure reading user command\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		size_t j = 0;
		while (cmd[j] != '\0') {
			cmd[j] = tolower((unsigned char)cmd[j]);
			j++;
		}	
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if (strcmp(cmd, "master") != 0 && strcmp(cmd, "account") != 0) {
			fprintf(stderr, "Please type either 'master' or 'account'\n");
		} else {
			break;
		}
	}
	int result;
	char *output;
	if (strcmp(cmd, "master") == 0) {
		printf("Master private key it is, serializing now...\n");
		result = serialize_extended_key(NULL, user->master_key, 1, &output);
	} else {
		printf("Account public key it is, serializing now...\n");
		uint32_t account_index;
		printf("What account do you want to use?\n\n"
		"Keep in mind that this wallet uses the derivation path of BIP84, which is: m/84'/0'/0'/0/0,\n"
		"meaning this is a Native Segwit (P2WPKH) account, its public addresses will always start with 'bc1q'.\n"
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
			printf("Enter account number between 0-3: (recommended - 0) > ");
			if (!fgets(cmd, sizeof(cmd), stdin)) {
				fprintf(stderr, "fgets failure\n");
				return 1;
			}
			cmd[strlen(cmd) - 1] = '\0';
			size_t j = 0;
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
		key_pair_t *coin_key = (key_pair_t *)g_malloc(sizeof(key_pair_t));
		if (!coin_key) {
			fprintf(stderr, "Error allocating\n");
			exit_handle(user);
		}
		if (derive_from_master_to_coin(user->master_key, coin_key) != 0) {
			fprintf(stderr, "Failure deriving coin key\n");
			g_free((void *)coin_key, sizeof(key_pair_t));
			exit_handle(user);
		}
		key_pair_t *account_key = g_malloc(sizeof(key_pair_t));
		if (!account_key) {
			fprintf(stderr, "Error allocating\n");
			g_free((void *)coin_key, sizeof(key_pair_t));
			exit_handle(user);
		}
		if (derive_child_key(coin_key, HARD_FLAG | account_index, account_key) != 0) {
			fprintf(stderr, "Failure deriving account key\n");
			g_free_multiple(sizeof(key_pair_t), (void *)coin_key, (void *)account_key, NULL);
			exit_handle(user);
		}
		result = serialize_extended_key(coin_key, account_key, 0, &output);
		g_free_multiple(sizeof(key_pair_t), (void *)coin_key, (void *)account_key, NULL);
	}
	if (result != 0) {
		fprintf(stderr, "Serialization error\n");
		return 1;
	}
	printf("Here is your serialized Base58-encoded address, write it down and keep it safe! (do not take a picture or save it on a computer)\n\n");
	printf(GREEN"%s\n\n"RESET, output);
	g_free((void *)output, strlen(output));
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
		"This does not necessarily mean that the funds aren't in your wallet associated with your seed phrase, however.\n"
		"Reminded: This wallet uses BIP84 derivation path: m/84'/0'/0'/0/0 (Native Segwit P2WPKH),\n"
		"its public addresses will always start with 'bc1q'.\n");
	char cmd[256];
	uint32_t account_index;
	while(1) {
		printf("Please enter the account number you'd like to see the balance of (between 0 - 100)\n"
			"Keep in mind that on this app, you are limited to only receiving funds on account 0-3,\n"
			"If you use a higher account on a different wallet software, we can scan it here, (up to 20 indexes).\n"
			"Enter account number to check balance on: > ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Failure reading account number\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		size_t j = 0;
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
		printf(GREEN"Total balance for this wallet, account %u:\n\n"
		"%lld satoshis (%.8f BTC)\n"
		"%.2f dollars (most recent price: $%.2f)\n"RESET,
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

int32 fee_handle(User *user) {
	long long regular_rate;
	long long priority_rate;
	
	if (get_fee_rate(&regular_rate, &priority_rate, &user->last_api_request) != 0) {
		fprintf(stderr, "Fee rate fetch failed.\n");
		return 1;
	}
	printf("Here are the current market fee rates (in satoshis):\n"
		"Regular (per bytes): %lld (%.8f BTC)\n"
		"Priority (per bytes): %lld (%.8f BTC)\n"
		GREEN"Regular total fee (estimated for typical transaction of 1 input and 2 outputs):\n"
		"%lld\n"
		"Priority total fee (estimated for typical transaction of 1 input and 2 outputs):\n"
		"%lld\n"RESET
		"A transaction of 1 input and 1 output is about 192 bytes.\n"
		"A transaction of 1 input and 2 outputs is about 226 bytes. (most common, this includes the 'change' back to yourself)\n"
		"A transaction of 2 input and 2 outputs is about 338 bytes.\n"
		"A transaction of 2 inputs and 2 outputs is about 374 bytes. (very common)\n",
		regular_rate, regular_rate / SATS_PER_BTC,
		priority_rate, priority_rate / SATS_PER_BTC,
		regular_rate * (long long)estimate_transaction_size(1, 2),
		priority_rate * (long long)estimate_transaction_size(1, 2));
	return 0;
}

int32 receive_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
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
		"that account 0 should be used instead.\n"
		"Reminded: This wallet uses BIP84 derivation path: m/84'/0'/0'/0/0 (Native Segwit P2WPKH),\n"
		"its addresses will always start with 'bc1q'.\n");

	while (1) {
		zero((void*)cmd, sizeof(cmd));
		printf("Enter account number between 0-3: (recommended - 0) > ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets failure\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		size_t j = 0;
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
			int result = scan_one_accounts_external_chain(user->master_key, index, &user->last_api_request);
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
	char address[ADDRESS_MAX_LEN];
	if (generate_receive_address(user->master_key, address, account_index, account->used_indexes_count) != 0) {
		fprintf(stderr, "Failure generating address.\n");
		return 1;
	}
	increment_account_used_index(account);
	// New receive address
	printf("New receive address:\n");
	printf(GREEN"%s\n"RESET, address);
	printf("Use this adddress to receive Bitcoin. You can:\n"
		"- Copy and share this address directly.\n"
		"- Generate a QR code by running a Linux tool like 'qrencode' (e.g. 'qrencode -o qrcode.png %s').\n"
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
		"This does not necessarily mean that the funds aren't in your wallet associated with your seed phrase, however.\n"
		"Reminded: This wallet uses BIP84 derivation path: m/84'/0'/0'/0/0 (Native Segwit P2WPKH),\n"
		"its public addresses will always start with 'bc1q'.\n");

	char cmd[256];
	uint32_t account_index;
	while(1) {
		printf("Please enter the account number you'd like to send from (between 0 - 100)\n"
			"We will query the blockchain to make sure you have enough UTXOs balance in this account to send funds.\n"
			"Enter account number: > ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Failure reading account number\n");
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		size_t j = 0;
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
	account_t *account = add_account_to_user(user, account_index);
	if (!account) {
		fprintf(stderr, "Failure allocating account\n");
		exit_handle(user);
	}
	printf("Please wait while we query the blockchain to check your UTXOs balance...\n(Account: %d, first 20 address indexes)\n", (int)account_index);
	utxo_t **utxos = NULL;
	int num_utxos = 0;
	long long total_balance = get_utxos_balance(user->master_key, &utxos, &num_utxos, account_index, &user->last_api_request);
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
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 0;
	}
	char recipient[ADDRESS_MAX_LEN];
	long long amount;
	printf("Enter recipient address, be sure to verify thoroughly:\n"
		"(we do not check and verify recipient address as of this version, please be sure to enter it correctly)\n> ");
	zero((void *)recipient, ADDRESS_MAX_LEN);
	if (!fgets(recipient, ADDRESS_MAX_LEN, stdin)) {
		fprintf(stderr, "Error reading command\n");
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 1;
	}
	recipient[strlen(recipient) - 1] = '\0';
	printf("Is this address correct?\n");
	printf(GREEN"%s\n"RESET, recipient);
	
	int result = command_loop(cmd, 256, "Type 'yes' or 'no'", "yes", "no", "Address confirmed.", "Try again later.");
	if (result < 0) {
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		exit_handle(user);
	} else if (result > 0) {
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 1;
	}
	while (1) {
		zero((void *)cmd, 256);
		printf("Enter amount you wish to send in satoshis (Your balance: %lld):\n"
		"> ", total_balance);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
		}
		amount = (long long)atoi(cmd);
		if (amount <= (long long) 0 || amount > total_balance) {
			fprintf(stderr, "Invalid amount, must be more than 0 and less than your total balance.\n");
			continue;
		} else {
			printf("Got it! Sending %lld sats/%lld available...\n", amount, total_balance);
			break;
		}
	}
	long long regular_rate;
	long long priority_rate;
	long long fee;
	
	if (get_fee_rate(&regular_rate, &priority_rate, &user->last_api_request) != 0) {
		fprintf(stderr, "Fee rate fetch failed.\n");
		free_utxos_array(utxos, &num_utxos, (size_t)num_utxos);
		return 1;
	}
	printf("Here are the current market fee rates (in satoshis):\n"
		"Regular (per bytes): %lld (%.8f BTC)\n"
		"Priority (per bytes): %lld (%.8f BTC)\n"
		GREEN"Regular total fee (estimated for typical transaction of 1 input and 2 outputs):\n"
		"%lld\n"
		"Priority total fee (estimated for typical transaction of 1 input and 2 outputs):\n"
		"%lld\n"RESET,
		regular_rate, regular_rate / SATS_PER_BTC,
		priority_rate, priority_rate / SATS_PER_BTC,
		regular_rate * (long long)estimate_transaction_size(1, 2),
		priority_rate * (long long)estimate_transaction_size(1, 2));
	printf("\nHow much would you like to spend on fees?\n"
		"Keep in mind, the higher you spend, the faster your transaction will be added to the next block.\n"
		"If you choose the regular fee rate, confirmation time will be ~1 hour.\n"
		"Or if you choose the priority rate, confirmation time will be ~10 minutes.\n"
		"You can choose a number lower than the regular rate, but that may leave your transaction in limbo for"
		" a long, indefinite, undefined amount of time\n");
	while (1) {
		printf("Enter how much you'd like to pay for miner fees (in satoshis, use the 'total fees' estimation above as benchmark): \n> ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
		}
		fee = (long long)atoi(cmd);
		if (fee <= (long long) 0 || fee + amount > total_balance) {
			fprintf(stderr, "Invalid fee amount, must be above 0 and less than total balance when added with amount to be sent.\n");
			continue;
		} else {
			printf("Got it! Paying %llu sats to miners\n", fee);	
			break;
		}
	}
	int rbf = 0;
	printf("Do you want to mark this transaction as RBF-enabled?\n\n"
		"(Replace-By-Fee: by having this enabled, you can later 'replace' the transaction in the mempool by doubling\n"
		"the fee-rate of the original transaction, essentially 'speeding up' how fast it ends up in the next block\n"
		"by incentivizing miners with a higher fee.)\n"); 
	result = command_loop(cmd, 256, "Type 'yes' or 'no'", "yes", "no", "RBF will be enabled.", "RBF not enabled.");
	if (result < 0) {
		exit_handle(user);
	} else if (result == 0) {
		rbf = 1;
	}
	utxo_t **selected = NULL;
	int num_selected = 0;
	long long input_sum = 0;
	printf("The program will now select the best UTXOs for this transaction, using a 'greedy' method,\n"
		"meaning that we will try to use the smallest number of UTXOs set possible, to save on fees.\n");
	if (select_coins(utxos, num_utxos, amount, fee, &selected, &num_selected, &input_sum) != 0 || num_selected == 0) {
		printf("Coin selection failed\n");
		return 1;
	}
	printf("Selected %d UTXOs, total: %lld satoshis\n", num_selected, input_sum);
	for (size_t i = 0; i < num_selected; i++) {
		printf("UTXO index=%ld: txid=%s, vout=%u, amount=%lld\n", 
			i, selected[i]->txid, selected[i]->vout, selected[i]->amount);
	}
	long long change = input_sum - amount - fee;
	key_pair_t *change_back_key = NULL;
	if (change > 0) {
		change_back_key = g_malloc(sizeof(key_pair_t));
		if (!change_back_key) {
			fprintf(stderr, "Failure allocating change_back_key\n");
			free_utxos_array(selected, &num_selected, (size_t)num_selected);
			return 1;
		}
		uint32_t child_index = account->used_indexes_count;
		if (derive_from_master_to_child(user->master_key, account_index, (uint32_t)1, child_index, change_back_key) != 0) {
			g_free((void *)change_back_key, sizeof(key_pair_t));	
			free_utxos_array(selected, &num_selected, (size_t)num_selected);
			return 1;
		}
		account->used_indexes_count++;
	}	

	char *raw_tx_hex = NULL;
	uint8_t *segwit_tx = NULL;
	size_t segwit_len = 0;
	if (build_transaction(recipient, amount, selected, num_selected, change_back_key, fee, &raw_tx_hex, &segwit_tx, &segwit_len, rbf) != 0) {
		fprintf(stderr, "Failure building transaction\n");
		free_utxos_array(selected, &num_selected, (size_t)num_selected);
		if (change_back_key) g_free((void *)change_back_key, sizeof(key_pair_t));	
		return 1;
	}
	if (change_back_key) g_free((void *)change_back_key, sizeof(key_pair_t));	
	printf("Successfully built transaction data\n");
	
	// Create transaction ID
	uint8_t txid[32];
	double_sha256(segwit_tx, segwit_len, txid);
	reverse_bytes(txid, 32);
	g_free(segwit_tx, segwit_len);
	// Sign
	if (sign_transaction(&raw_tx_hex, selected, num_selected) != 0) {
		fprintf(stderr, "Failure signing transaction\n");
		free_utxos_array(selected, &num_selected, (size_t)num_selected);
		g_free((void *)raw_tx_hex, strlen(raw_tx_hex));
		return 1;
	}
	free_utxos_array(selected, &num_selected, (size_t)num_selected);
	printf("Successfully signed transaction data\n");
	if (broadcast_transaction(raw_tx_hex, &user->last_api_request) != 0) {
		fprintf(stderr, "Failure broadcasting transaction\n");
		g_free((void *)raw_tx_hex, strlen(raw_tx_hex));
		return 1;
	}
	printf("This is your transaction ID, (in reverse byte order as per conventional blockchain explorers' standards) track it on the blockchain:\n");
	print_bytes_as_hex("TXID", txid, 32);
	g_free((void *)raw_tx_hex, strlen(raw_tx_hex));
	return 0;
}

int32 rbf_handle(User *user) {
	if (!has_wallet(user)) {
		printf("No wallet available for this command. Please generate a new wallet or recover your existing one.\n"
		"Type 'new' or 'recover' to begin\n");
		return 1;
	}
	printf("This feature requires that you have a previous Replace-By-Fee enabled transaction currently in the mempool.\n"
		"By sending a new transaction with 2x the previous transaction's feerate, you will incentivize miners\n"
		"to be much more likely to include it into the next block.\n");
	char cmd[256];
	while (1) {
		zero((void *)cmd, 256);
		printf("Do you have an RBF-enabled transaction currently in the mempool?\nType 'yes' or 'no' > ");
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			continue;
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
			printf("Got it. Let's begin building a new transaction with double the previous fee.\n");
			break;
		} else if (strcmp(cmd, "no") == 0) {
			printf("This feature requires an existing RBF-enabled transaction. Try sending a new transaction with RBF on first.\n");
			return 0;
		}
	}
	printf("Please provide the transaction ID of the unconfirmed RBF-enabled tx in the mempool you'd like to replace.\n");
	char tx_id[256];
	while (1) {
		printf("TXID > ");
		zero((void *)tx_id, 256);
		if (!fgets(tx_id, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			return 1;
		}
		tx_id[strlen(tx_id) - 1] = '\0';
		if (strlen(tx_id) != 64) {
			fprintf(stderr, "Transaction ID must be 64 hexadecimal characters (32 bytes). Try again.\n");
			continue;	
		} else {
			printf("Got it! Querying mempool for transaction ID %s...\n", tx_id);	
			break;
		}
	}
	rbf_data_t *rbf_data = (rbf_data_t *)g_calloc(sizeof(rbf_data_t));
	if (!rbf_data) {
		fprintf(stderr, "Error allocating rbf_data\n");
		return 1;
	}
	if (query_rbf_transaction(tx_id, &rbf_data, &user->last_api_request) != 0) {
		fprintf(stderr, "Unable to fetch transaction\n");
		g_free((void *)rbf_data, sizeof(rbf_data_t));
		return 1;	
	}

	// Uncomment this later, only blocking it for testing
/*
	if (rbf_data->unconfirmed == 0) {
		fprintf(stderr, "This transaction is already confirmed.\n");
		return 1;
	}
*/
	printf("Found unconfirmed transaction.\n");
	if (fetch_rbf_raw_tx_hex(tx_id, rbf_data, &user->last_api_request) != 0) {
		fprintf(stderr, "Unable to fetch raw transaction hex data\n");
		free_utxos_array(rbf_data->utxos, &(rbf_data->num_inputs), (size_t)rbf_data->num_inputs);
		free_rbf_outputs_array(rbf_data->outputs, (size_t)rbf_data->num_outputs);
		g_free((void *)rbf_data, sizeof(rbf_data_t));
		return 1;
	}

	if (check_rbf_sequence(rbf_data->raw_tx_hex, rbf_data->num_inputs) != 0) {
		fprintf(stderr, "This transaction does not have RBF enabled on any of its inputs. Try a different transaction.\n");
		free_utxos_array(rbf_data->utxos, &(rbf_data->num_inputs), (size_t)rbf_data->num_inputs);
		free_rbf_outputs_array(rbf_data->outputs, (size_t)rbf_data->num_outputs);
		g_free((void *)rbf_data, sizeof(rbf_data_t));
		return 1;
	}
	printf("Transaction has RBF enabled, proceeding...\n");
	printf("What was the account index used to derive the UTXO input(s) for this transaction?\n"
		"In order to build and sign a new replacement transaction, we will attempt to\n"
		"locate and match a private key to your UTXO input(s)\n");
	while (1) {
		printf("Please enter account index (0 - 100) (must match account used to build original transaction)\n> ");
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Failure reading account number\n");		
			free_complete_rbf(rbf_data);
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
			rbf_data->account_index = (uint32_t)atoi(cmd);
			printf("Got it. We will query account index %d to match your UTXO(s)' keys.\n", (int)rbf_data->account_index);
			break;
		}
	}
	account_t *account = add_account_to_user(user, rbf_data->account_index);
	if (!account) {
		fprintf(stderr, "Failure adding account\n");
		free_complete_rbf(rbf_data);
		return 1;
	}
	if (match_utxos_to_keys(user->master_key, rbf_data) != 0) {
		fprintf(stderr, "Failure matching UTXOs to private keys.\n");
		free_complete_rbf(rbf_data);
		return 1;
	}	
	
	if (calculate_rbf_fee(rbf_data, 2, &user->last_api_request) != 0) {
		fprintf(stderr, "Failure calculating RBF fee\n");
		free_complete_rbf(rbf_data);
		return 1;
	}
	while (1) {
		printf("The new fee amount is %lld sats. Proceed?\nType 'yes' or 'no' (or 'exit' to quit) > ", rbf_data->new_fee);
		zero((void *)cmd, 256);
		if (!fgets(cmd, 256, stdin)) {
			fprintf(stderr, "Error reading command\n");
			free_complete_rbf(rbf_data);
			return 1;
		}
		cmd[strlen(cmd) - 1] = '\0';
		int i = 0;
		while (cmd[i] != '\0') {
			cmd[i] = tolower((unsigned char)cmd[i]);
			i++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle(user);
		if (strcmp(cmd, "yes") == 0) {
			printf("Got it, let's check if you already have a change output.\n");
			break;
		} else if (strcmp(cmd, "no") == 0) {
			printf("Okay, cancelling RBF transaction.\n");
			free_complete_rbf(rbf_data);
			return 1;
		} else {
			fprintf(stderr, "Invalid response, 'yes', 'no', or 'exit' only\n");
			continue;
		}
	}
	int result;	
	if (rbf_data->num_outputs > 1) {
		printf("Your previous transaction had %d total recipients. Please confirm that you only had %d intended\n"
			"recipient address(es), and that the last one is your change address.\n"
			"This will effectively decrease the last recipient's (your change address) output amount\n"
			"in order to pay the difference in miner's fee.\n"
			"(Explanation: If a transaction's input(s) exceeds the output(s), there is always an automatic 'change address'\n"
			"generated to send the remaining sats back to you.\n", (int)rbf_data->num_outputs, (int)rbf_data->num_outputs - 1);
		result = command_loop(cmd, 256, "Confirm with 'yes' or 'no' >",
					"yes", "no",
					"Got it, we will modify the existing change output (the last recipient address) to accomodate the new fee.",
					"Unfortunately, that means your input UTXO(s) will not have enough sats to cover the additional fee."
                                        "Your old transaction will remain in the mempool for around 2 weeks, and if it's not picked up"
                                        "by a miner to be mined into a block, it will simply 'fall off' of no consequence to you."
                                        "In the meantime, you can make a new transaction, but not with those same UTXOs that are currently"
                                        "'stuck' in the mempool."
                                	"Another valid option is to simply decrease the amount sent to the last recipient address of your original"
                                        "transaction. The difference in fee will be subtracted from that output in order to pay the miners."
                                        "If you want this option, restart the 'rbf' command again and say 'yes' to decreasing the last recipient's"
                                        "output amount to pay the miner's fee.");
		if (result < 0) {
			free_complete_rbf(rbf_data);
			exit_handle(user);
		} else if (result > 0) {
			free_complete_rbf(rbf_data);
			return 1;
		}
	} else {
		printf("It seems you only have 1 output in the original transaction. You can still make a new RBF replacement transaction\n"
			"if you decrease the output amount for this recipient in order to pay the difference in fees.\n"
			"Would you still like to proceed? >");
		result = command_loop(cmd, 256, "Type 'yes' or 'no'", 
					"yes", "no",
					"Got it, we will modify the existing change output (the last recipient address) to accomodate the new fee.",
					"Unfortunately, that means your input UTXO(s) will not have enough sats to cover the additional fee."
                                        "Your old transaction will remain in the mempool for around 2 weeks, and if it's not picked up"
                                        "by a miner to be mined into a block, it will simply 'fall off' of no consequence to you."
                                        "In the meantime, you can make a new transaction, but not with those same UTXOs that are currently"
                                        "'stuck' in the mempool."
                                	"Another valid option is to simply decrease the amount sent to the last recipient address of your original"
                                        "transaction. The difference in fee will be subtracted from that output in order to pay the miners."
                                        "If you want this option, restart the 'rbf' command again and say 'yes' to decreasing the last recipient's"
                                        "output amount to pay the miner's fee.");
		if (result < 0) {
			free_complete_rbf(rbf_data);
			exit_handle(user);
		} else if (result > 0) {
			free_complete_rbf(rbf_data);
			return 1;
		}
	}	
	char *raw_tx_hex = NULL;
	uint8_t *segwit_tx = NULL;
	size_t segwit_len = 0;
	if (build_rbf_transaction(rbf_data, &raw_tx_hex, &segwit_tx, &segwit_len) != 0) {
		fprintf(stderr, "Failure building RBF transaction.\n");
		free_complete_rbf(rbf_data);
		return 1;
	}
	printf("Successfully built new RBF transaction data.\n");
	// Create transaction ID
	uint8_t txid[32];
	double_sha256(segwit_tx, segwit_len, txid);
	reverse_bytes(txid, 32);
	g_free((void *)segwit_tx, segwit_len);
	// Sign
	if (sign_transaction(&raw_tx_hex, rbf_data->utxos, rbf_data->num_inputs) != 0) {
		fprintf(stderr, "Failure signing RBF transaction.\n");
		free_complete_rbf(rbf_data);
		g_free((void *)raw_tx_hex, strlen(raw_tx_hex));
		return 1;
	}
	printf("Successfully signed transaction data\n");
	if (broadcast_transaction(raw_tx_hex, &user->last_api_request) != 0) {
		fprintf(stderr, "Failure broadcasting transaction\n");
		free_complete_rbf(rbf_data);
		g_free((void *)raw_tx_hex, strlen(raw_tx_hex));
		return 1;
	}
	printf("Broadcast successful.\n");
	printf("This is your transaction ID, (in reverse byte order as per conventional blockchain explorers' standards) track it on the blockchain:\n");
	print_bytes_as_hex("TXID", txid, 32);
	free_complete_rbf(rbf_data);
	g_free((void *)raw_tx_hex, strlen(raw_tx_hex));
	return 0;
}

int32 help_handle(User *user) {
	printf("Coming soon... :)\n");
	return 0;
}

int32 menu_handle(User *user) {
	print_menu();
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
	init_gcrypt();
	User *user;
	user = (User *)g_malloc(sizeof(User));
	if (!user) {
		fprintf(stderr, "Failure to allocate user\n");
		return 1;
	}
	print_logo();
	if (init_user(user) != 0) {
		fprintf(stderr, "User secured allocation and setup failed.\n");
		gcry_free((void *)user);
		return 1;
	}
	print_menu();
	main_loop(user);
	free_user(user);
	free_all();
	return 0;
}
