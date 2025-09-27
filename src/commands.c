/* commands.c */

#include "commands.h"

void print_green(const char *command) {
	printf(GREEN"%s\n"RESET, command);
}

void print_red(const char *command) {
	printf(RED"%s\n"RESET, command);
}

void print_commands(const char *commands, ...) {
	va_list args;
	if (commands) {
		printf("%s\n", commands);
	}
	va_start(args, commands);
	const char *ptr;
	while ((ptr = va_arg(args, const char *)) != NULL) {
		printf("%s\n", ptr);
        }
        va_end(args);
}

int command_loop(char *buffer, size_t len, const char *command, const char *pass, const char *fail, const char *pass_reply, const char *fail_reply) {
	while (1) {
		memset(buffer, 0, len);
		printf(YELLOW"%s\n"RESET, command);
		printf("> ");
		if (!fgets(buffer, len, stdin)) {
			fprintf(stderr, "Error reading command\n");
			return -1;
		}
		buffer[strlen(buffer) - 1] = '\0';
		size_t i = 0;
		while (buffer[i] != '\0') {
			buffer[i] = tolower((unsigned char)buffer[i]);
			i++;
		}
		if (strncmp(buffer, pass, strlen(buffer)) != 0 && strncmp(buffer, fail, strlen(buffer)) != 0) {
			printf("Invalid input. Only accepting '%s' or '%s'.\n", pass, fail);
			continue;
		} else if (strncmp(buffer, pass, strlen(buffer)) == 0) {
			printf("%s\n", pass_reply);
			return 0;
		} else if (strncmp(buffer, fail, strlen(buffer)) == 0) {
			printf("%s\n", fail_reply);
			return 1;
		} else if (strncmp(buffer, "exit", strlen(buffer)) == 0) {
			printf("Exiting...\n");
			return -1;
		}
	}
}


