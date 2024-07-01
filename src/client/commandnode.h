#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "linkedlist.h"

#define MAX_COMMAND_NAME_LENGTH 256

// Command function typedef
typedef char* (*CommandFunction)(char*);

// Node structure for the linked list
typedef struct CommandNode {
    char command[MAX_COMMAND_NAME_LENGTH];  // Command name
    CommandFunction function;               // Pointer to command function
} CommandNode;

typedef CommandNode* (*CommandNodePointer)(void);

CommandNode* createCommandNode(char* commandName, CommandFunction function);
void deleteCommandNode(LinkedList* list, char* commandName);
char* getCommands(LinkedList* list, const char* prepend);
void insertCommandNode(LinkedList* list, CommandNode* data);
CommandNode* findCommandNode(LinkedList* list, char* commandName);


#endif /* COMMANDS_H */