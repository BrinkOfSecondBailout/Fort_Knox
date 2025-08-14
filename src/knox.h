/* knox.h */

#ifndef KNOX_H
#define KNOX_H

typedef unsigned int int32;

typedef int32 (*Callback)();

typedef struct {
	char *command_name;
	Callback call_back_function;
} Command_Handler;

int32 new_handle();
int32 help_handle();
int32 menu_handle();
int32 exit_handle();
#endif
