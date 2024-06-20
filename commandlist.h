#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_COMMAND_NAME_LENGTH 256

// Command function typedef
typedef char* (*CommandFunction)(char*);

// Node structure for the linked list
typedef struct CommandNode {
    char command[MAX_COMMAND_NAME_LENGTH];  // Command name
    CommandFunction function;               // Pointer to command function
    struct CommandNode* next;               // Pointer to next node
} CommandNode;

typedef CommandNode* (*CommandNodePointer)(void);

CommandNode* createCommandNode(char* commandName, CommandFunction function);
void insertCommandNode(CommandNode** head, CommandNode* newNode);
CommandNode* findCommandNode(CommandNode* head, char* commandName);
void deleteCommandNode(CommandNode** head, char* commandName);
void printCommands(CommandNode* head);
char* getCommands(CommandNode* head, char* prepend);

// Get functionality of command by name and execute it
void executeCommand(CommandNode* head, char* commandName, char* arguments);

// Function to create a new command node
CommandNode* createCommandNode(char* commandName, CommandFunction function)
{
    CommandNode* newNode = (CommandNode*)malloc(sizeof(CommandNode));
    if (newNode != NULL)
    {
        strncpy(newNode->command, commandName, MAX_COMMAND_NAME_LENGTH);
        newNode->command[MAX_COMMAND_NAME_LENGTH - 1] = '\0';
        newNode->function = function;
        newNode->next = NULL;
    }
    return newNode;
}

// Insert a command node into the linked list
void insertCommandNode(CommandNode** head, CommandNode* newNode)
{
    if (*head == NULL)
    {
        *head = newNode;
    }
    else
    {
        CommandNode* current = *head;
        while (current->next != NULL)
        {
            current = current->next;
        }
        current->next = newNode;
    }
}

// Find a command node by name
CommandNode* findCommandNode(CommandNode* head, char* commandName)
{
    CommandNode* current = head;
    while (current != NULL)
    {
        if (strcmp(current->command, commandName) == 0)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// Execute a command by name
void executeCommand(CommandNode* head, char* commandName, char* arguments)
{
    CommandNode* commandNode = findCommandNode(head, commandName);
    if (commandNode != NULL)
    {
        commandNode->function(arguments);
    }
}

// Print all commands in the linked list
// TODO: Turn this into a return to server instead of print
void printCommands(CommandNode* head)
{
    CommandNode* current = head;
    printf("Valid Commands:\n");
    while (current != NULL)
    {
        printf("%s\n", current->command);
        current = current->next;
    }
}

// Return all commands in the linked list
char* getCommands(CommandNode* head, char* prepend)
{
    CommandNode* current = head;
    int buffer_offset = 0;
    int buffer_length = 256;
    
    // Make sure prepend isn't too big for the buffer
    if (strlen(prepend) >= buffer_length)
        return NULL;
    
    char* buffer = (char*)calloc(buffer_length,sizeof(char));

    if (prepend)
    {
        strcat(buffer, prepend);
        buffer_offset += strlen(prepend);
    }

    printf("starting loop.\n");
    while (current != NULL)
    {
        int command_length = strlen(current->command);
        printf("inserting command: %s %d\n", current->command, command_length);
        if ((command_length + buffer_offset + 2) > buffer_length)
        {
            // Reallocate memory to fit the new data
            char *ptr_realloc = realloc(buffer, buffer_length + command_length + 256);
            if (ptr_realloc == NULL)
            {
                fprintf(stderr, "Memory allocation failed\n");
                return NULL;
            }
             buffer = ptr_realloc;
        }
        printf("adding to buffer\n");
        strcat(buffer, current->command);
        buffer_offset += command_length;
        memset(&(buffer[buffer_offset]), ' ', 1);
        buffer_offset += 1;
        current = current->next;
        printf("moving to next\n");
    }
    printf("buffer: %s\n", buffer);
    return buffer;
}

void deleteCommandNode(CommandNode** head, char* commandName)
{
    CommandNode* current = *head;
    CommandNode* prev = NULL;

    // Traverse the linked list to find the node to delete
    while (current != NULL)
    {
        if (strcmp(current->command, commandName) == 0)
        {
            // Found the node to delete
            if (prev == NULL)
                *head = current->next; // If the node to delete is the head node
            else
                prev->next = current->next;
            free(current);
            current = NULL;
            return; // Node deleted, exit function
        }
        // Move to the next node
        prev = current;
        current = current->next;
    }
}

#endif /* COMMANDS_H */