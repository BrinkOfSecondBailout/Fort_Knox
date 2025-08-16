/* knox.c */

#include "knox.h"
#include "common.h"
#include "wallet.h"
#include "crypt.h"

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
		printf("%s", buffer);
		fflush(stdout);
		usleep(100000);
	}
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
	"- balance			Display balance for all addresses in wallet\n"
	"- help				Safety practices, tips, and educational contents\n"
	"- menu				Show all commands\n"
	"- exit				Exit program\n");
	return;
}

Command_Handler c_handlers[] = {
	{ (char *)"new", new_handle},
	{ (char *)"help", help_handle},
	{ (char *)"menu", menu_handle},
	{ (char *)"exit", exit_handle}
};

int32 exit_handle() {
	printf("Bye now, bitcoiner!\n");
	exit(0);
}

int32 new_handle() {
	init_gcrypt();
	fprintf(stdout, "Generating a standard BIP84 Bitcoin wallet... keys derivation scheme below.\n");
	//key_pair_t key_pair = {0};
	char cmd[255];
	while (1) {
		zero(cmd, sizeof(cmd));
		printf("Select your recovery seed words count (12, 15, 18, 21, 24)\n"
			"Note: the higher the number, the larger the entropy AKA more cryptographically secured\n> ");
		if (!fgets(cmd, sizeof(cmd), stdin)) {
			fprintf(stderr, "fgets() failure\n");
		}
		cmd[strlen(cmd)] = '\0';
		if (strcmp(cmd, "exit") == 0) exit_handle();
		int nword = atoi(cmd);
		if (nword != 12 && nword != 15 && nword != 18 && nword != 21 && nword != 24) {
			fprintf(stderr, "Please select a valid number - only 12, 15, 18, 21, 24 allowed\n");
		} else {
			break;
		}
	}

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
	print_commands();
	main_loop();
	return 0;
}
