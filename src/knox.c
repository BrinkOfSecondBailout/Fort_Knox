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

void print_logo() {
	FILE *logo = fopen("logo.txt", "r");
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), logo)) {
		printf(CYAN"%s", buffer);
		fflush(stdout);
		usleep(100000);
	}
	printf(RESET);
	fclose(logo);
	return;
}

void print_commands() {
	fprintf(stdout, "Welcome bitcoiner! What is your command?\n"
	"- new				Creates a new Bitcoin wallet\n"
	"- key				Display wallet root private key (NEVER SHOW THIS TO ANYONE)\n"
	"- addresses			Display all bitcoin addresses in wallet\n"
	"- keys				Display all bitcoin addresses and corresponding private keys for each\n"
	"- recover			Recovers your bitcoin wallet with mnemonic words(& passphrase, if set)\n"
	"- receive			Receive bitcoin with a new bitcoin address\n"
	"- balance			Display balance for all addresses in current wallet\n"
	"- help				Safety practices, tips, and educational contents\n"
	"- menu				Show all commands\n"
	"- exit				Exit program\n\n");
	return;
}

Command_Handler c_handlers[] = {
	{ (char *)"new", new_handle},
	{ (char *)"balance", balance_handle},
	{ (char *)"help", help_handle},
	{ (char *)"menu", menu_handle},
	{ (char *)"exit", exit_handle}
};

int32 exit_handle() {
	printf("Bye now, bitcoiner!\n");
	exit(0);
}

int32 new_handle() {
	printf("Generating a standard BIP44 Bitcoin wallet...\n"
		"If this program is running locally, strongly recommended that you disconnect from the internet for extra security\n");
	key_pair_t key_pair = {0};
	char mnemonic[256];
	char passphrase[256];
	char cmd[255];
	int nword;
	while (1) {
		zero(cmd, sizeof(cmd));
		printf("\nSelect your recovery seed words count (12, 15, 18, 21, 24)\n"
			"Note: the higher the number, the larger the entropy AKA more cryptographically secured\n> ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd)] = '\0';
		if (strcmp(cmd, "exit") == 0) exit_handle();
		nword = atoi(cmd);
		if (nword != 12 && nword != 15 && nword != 18 && nword != 21 && nword != 24) {
			fprintf(stderr, "\nPlease select a valid number - only 12, 15, 18, 21, 24 allowed\n");
		} else {
			break;
		}
	}
	printf("Got it! %d words it is..\n", nword);
	while (1) {
		printf("\nWould you like to add an additional passphrase on top of the mnemonic seed words for extra security?\nReply 'yes' or 'no'> ");
		zero(cmd, sizeof(cmd));
		zero(passphrase, sizeof(passphrase));
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		int i = 0;
		while (cmd[i] != '\0') {
			cmd[i] = tolower((unsigned char)cmd[i]);
			i++;
		}
		if (strcmp(cmd, "exit") == 0) exit_handle();
		if ((strcmp(cmd, "yes") != 0) && (strcmp(cmd, "no") != 0)) {
			fprintf(stderr, "\nInvalid answer, must type 'yes' or 'no'\n");
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

	if (generate_mnemonic(nword, passphrase, mnemonic, sizeof(mnemonic), &key_pair) == 0) {
		printf("\nHere is your brand new bitcoin wallet's mnemonic seed words:\n"
			"\n\n"
			GREEN"%s\n"RESET
			"\n\n"
			RED"IMPORTANT:"RESET 
			" Please write these words down very carefully on a piece of paper\n"
			"Do NOT type or save these words on any electronic devices\n"
			" Losing these words or having them stolen = losing all of your bitcoin\n", mnemonic);
		if (passphrase[0]) {
			printf(RED"ALSO IMPORTANT:"RESET 
			" Those are ONLY the %d mnemonic seed words\n"
			"but since you added a passphrase, (not listed above), you WILL be responsible\n" 
			"for having it if you want access to the funds sent to this wallet.\n"
			RED"If you attempt to recover this wallet with only your seed words and the incorrect or blank passphrase,\n"
			"you will see a completely different wallet, not the one you're about to use to send funds to\n"RESET, nword);
		}	
	}
	return 0;
}

int32 balance_handle() {
	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl_global_cleanup();
	return 0;
}

int32 help_handle() {
	return 0;
}

int32 menu_handle() {
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

void main_loop() {
	char buf[256], cmd[256];
	while (1) {
		zero_multiple(buf, cmd, NULL);	
		printf("> ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd) - 1] = '\0';
		Callback cb = get_command(cmd);
		if (!cb) {
			printf("Invalid command\n");
			continue;
		}
		cb();
	}
}

int main() {
	print_logo();
	init_gcrypt();
	print_commands();
	main_loop();
	return 0;
}
