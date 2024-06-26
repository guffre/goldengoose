#include "commandnode.h"

// Insert a command node into the linked list
void insertCommandNode(LinkedList* list, CommandNode* data)
{
    Node* node = create_node(data);
    // No effect if failed to create node
    append_node(list, node);
}

// Function to create a new command node
CommandNode* createCommandNode(char* commandName, CommandFunction function)
{
    CommandNode* newNode = (CommandNode*)malloc(sizeof(CommandNode));
    if (newNode != NULL)
    {
        strncpy(newNode->command, commandName, MAX_COMMAND_NAME_LENGTH);
        newNode->command[MAX_COMMAND_NAME_LENGTH - 1] = '\0';
        newNode->function = function;
    }
    return newNode;
}

// Find a command node by name
CommandNode* findCommandNode(LinkedList* list, char* commandName)
{
    Node* current = list->head;
    while (current != NULL)
    {
        CommandNode* command = (CommandNode*)current->data;
        if (strcmp(command->command, commandName) == 0)
        {
            return command;
        }
        current = current->next;
    }
    return NULL;
}

void deleteCommandNode(LinkedList* list, char* commandName)
{
    Node* current = list->head;

    // Traverse the linked list to find the node to delete
    while (current != NULL)
    {
        CommandNode* command = (CommandNode*)current->data;
        if (strcmp(command->command, commandName) == 0)
        {
            // Found the node to delete
            SAFE_FREE(command);
            delete_node(list, current);
            return; // Node deleted, exit function
        }
        // Move to the next node
        current = current->next;
    }
}

// Return all commands in the linked list
char* getCommands(LinkedList* list, const char* prepend)
{
    Node* current = list->head;
    int buffer_offset = 0;
    int buffer_length = 256;
    
    // Make sure prepend isn't too big for the buffer
    if (prepend && strlen(prepend) >= buffer_length)
        return NULL;
    
    char* buffer = (char*)calloc(buffer_length,sizeof(char));

    if (prepend)
    {
        strcat(buffer, prepend);
        buffer_offset += strlen(prepend);
    }

    while (current != NULL)
    {
        CommandNode* command = (CommandNode*)current->data;
        int command_length = strlen(command->command);
        debugf("inserting command: %s %d\n", command->command, command_length);
        if ((command_length + buffer_offset + 2) > buffer_length)
        {
            // Reallocate memory to fit the new data
            char *ptr_realloc = realloc(buffer, buffer_length + command_length + 256);
            if (ptr_realloc == NULL)
            {
                debugf("Memory allocation failed\n");
                return NULL;
            }
             buffer = ptr_realloc;
        }
        debugf("adding to buffer\n");
        strcat(buffer, command->command);
        buffer_offset += command_length;
        memset(&(buffer[buffer_offset]), ' ', 1);
        buffer_offset += 1;
        current = current->next;
        debugf("moving to next\n");
    }
    debugf("buffer: %s\n", buffer);
    return buffer;
}