#include <stdio.h>
#include <stdlib.h>

// Base64 dictionary
static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    unsigned char **buffers; // Array of pointers to the compressed data buffers
    unsigned long *sizes;   // Array of sizes of each compressed buffer
    int count;      // Number of buffers (number of monitors)
} DataBlobs;

//////////////////////////////////////// LINKED LIST START
typedef struct Command {
    char command[256];
    void (*command_func)(void);
} Command;

struct Node {
    Command data;
    struct Node* next;
};

// Function declarations
void insertAtBeginning(struct Node** head_ref, Command new_data);
void insertAtEnd(struct Node** head_ref, Command new_data);
void deleteNode(struct Node** head_ref, char* command);
void printList(struct Node* node);

//////////////////////////////////////// LINKED LIST END

//////////////////////////////////////// CODE START
//////////////// LINKED LIST CODE
// Function to insert a node at the beginning of the list
void insertAtBeginning(struct Node** head_ref, Command new_data) {
    struct Node* new_node = (struct Node*)malloc(sizeof(struct Node));
    new_node->data = new_data;
    new_node->next = (*head_ref);
    (*head_ref) = new_node;
}

// Function to insert a node at the end of the list
void insertAtEnd(struct Node** head_ref, Command new_data) {
    struct Node* new_node = (struct Node*)malloc(sizeof(struct Node));
    struct Node* last = *head_ref;
    new_node->data = new_data;
    new_node->next = NULL;
    if (*head_ref == NULL) {
        *head_ref = new_node;
        return;
    }
    while (last->next != NULL) {
        last = last->next;
    }
    last->next = new_node;
}

// Function to delete a node by command
void deleteNode(struct Node** head_ref, char* command) {
    struct Node* temp = *head_ref;
    struct Node* prev = NULL;
    if (temp != NULL && strcmp(temp->data.command, command) == 0) {
        *head_ref = temp->next;
        free(temp);
        return;
    }
    while (temp != NULL && strcmp(temp->data.command, command) != 0) {
        prev = temp;
        temp = temp->next;
    }
    if (temp == NULL) return;
    prev->next = temp->next;
    free(temp);
}

// Function to print the linked list
void printList(struct Node* node) {
    while (node != NULL) {
        printf("Command: %s\n", node->data.command);
        node = node->next;
    }
}
//////////////// LINKED LIST CODE END

//////////////// BLOB/BASE64 CODE
void FreeBlobs(DataBlobs* data)
{
    if (data) {
        for (int i = 0; i < data->count; ++i) {
            free(data->buffers[i]);
        }
        free(data->buffers);
        free(data->sizes);
        free(data);
    }
}

int Base64Encode(const unsigned char* buffer, int length, char* base64Buffer) {
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int base64Length = 0;

    while (length--) {
        char_array_3[i++] = *(buffer++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++) {
                base64Buffer[base64Length++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++) {
            base64Buffer[base64Length++] = base64_chars[char_array_4[j]];
        }

        while ((i++ < 3)) {
            base64Buffer[base64Length++] = '=';
        }
    }

    return base64Length;
}
//////////////// BLOB/BASE64 CODE END

void BREAK_WITH_ERROR(char *err) {
	printf("\n%s\n", err);
	exit(3);
}

#ifdef _WIN32
#include <Windows.h>
ULONG_PTR ReflectiveLoader( LPVOID lpAddr );
#endif