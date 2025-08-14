/* knox.h */

#ifndef KNOX_H
#define KNOX_H

typedef unsigned int int32;

typedef int32 (Callback*)();

typedef struct {
	char *command_name;
	Callback call_back_function;
} Command_Handler;

#endif
