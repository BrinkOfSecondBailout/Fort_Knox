/* knox.c */

#include "knox.h"
#include "common.h"

Commahd_Handler c_handlers[] = {
	{ (char *)"new", new_handle},
	{ (char *)"key", key_handle},
	{ (char *)"addresses", addresses_handle},
	{ (char *)"keys", keys_handle},
	{ (char *)"recover", recover_handle},
	{ (char *)"receive", receive_handle},
	{ (char *)"balance", balance_handle},
	{ (char *)"help", help_handle},
	{ (char *)"menu", menu_handle},
};

void print_logo() {
	FILE *logo = fopen("logo.txt", "r");
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), logo)) {
		printf("%s", buffer);
		fflush(stdout);
		usleep(100000);
	}
	fclose(logo);
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
	"- menu				Show all commands\n");
}

void main_loop() {
	while () {

	}	
}

int main() {
	print_logo();
	print_commands();
	main_loop();
	return 0;
}
