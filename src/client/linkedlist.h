#ifndef LINKEDLIST_H
#define LINKEDLIST_H

#include <stdio.h>
#include <stdlib.h>

#include "common.h"

// Node structure
typedef struct Node {
    void *data;
    struct Node *next;
} Node;

// Linked list structure
typedef struct LinkedList {
    Node *head;
    Node *tail;
} LinkedList;

// Function to create a new node
Node *create_node(void *data);

// Function to create a new linked list
LinkedList *create_list(void);

// Function to append a node to the linked list
void append_node(LinkedList *list, Node *new_node);

// Function to delete a node from the linked list
void delete_node(LinkedList *list, Node *node);

// Function to delete the entire linked list
void delete_list(LinkedList *list);

#endif