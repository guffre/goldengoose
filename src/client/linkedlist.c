#include "linkedlist.h"

Node *create_node(void *data)
{
    Node *new_node = (Node*)malloc(sizeof(Node));
    if (!new_node)
    {
        debugf("Memory allocation failed\n");
        return NULL;
    }
    new_node->data = data;
    new_node->next = NULL;
    return new_node;
}

LinkedList *create_list(void)
{
    LinkedList *list = (LinkedList *)malloc(sizeof(LinkedList));
    if (!list)
    {
        debugf("Memory allocation failed\n");
        return NULL;
    }
    list->head = NULL;
    list->tail = NULL;
    return list;
}

void append_node(LinkedList *list, Node *new_node)
{
    if (!list->tail)
    { // If list is empty
        list->head = new_node;
        list->tail = new_node;
    }
    else
    {
        list->tail->next = new_node;
        list->tail = new_node;
    }
}

void delete_node(LinkedList *list, Node *node)
{
    if (!list->head)
    {
        return; // List is empty
    }

    if (list->head == node)
    { // Node is at the head
        list->head = list->head->next;
        if (!list->head)
        { // List is now empty
            list->tail = NULL;
        }
        free(node);
        return;
    }

    Node *current = list->head;
    while (current->next && current->next != node)
    {
        current = current->next;
    }

    if (current->next == node)
    {
        current->next = node->next;
        if (!current->next)
        { // Node was at the tail
            list->tail = current;
        }
        free(node);
    }
}

void delete_list(LinkedList *list)
{
    Node *current = list->head;
    Node *next_node;
    while (current)
    {
        next_node = current->next;
        free(current);
        current = next_node;
    }
    free(list);
}

// // Helper function to print the list (for demonstration purposes)
// void print_list(LinkedList *list, void (*print_func)(void *))
// {
//     Node *current = list->head;
//     while (current)
//     {
//         print_func(current->data);
//         current = current->next;
//     }
//     printf("\n");
// }

// // Example print function for integers
// void print_int(void *data)
// {
//     printf("%d -> ", *(int *)data);
// }

// int main()
// {
//     LinkedList *list = create_list();

//     int data1 = 1, data2 = 2, data3 = 3;
//     Node *node1 = create_node(&data1);
//     Node *node2 = create_node(&data2);
//     Node *node3 = create_node(&data3);

//     append_node(list, node1);
//     append_node(list, node2);
//     append_node(list, node3);

//     printf("Initial list: ");
//     print_list(list, print_int);

//     delete_node(list, node2);

//     printf("After deleting node with data 2: ");
//     print_list(list, print_int);

//     delete_list(list);

//     return 0;
// }