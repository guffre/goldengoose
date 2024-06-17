#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>

#define CHECK_FREE_NULL(x) {if(x) {free(x); x=NULL;};}

typedef struct {
    unsigned char **buffers; // Array of pointers to the compressed data buffers
    unsigned long *sizes;    // Array of sizes of each compressed buffer
    int count;               // Number of buffers (number of monitors)
} DataBlobs;

void FreeBlobs(DataBlobs* data);

#ifdef _WIN32
#include <Windows.h>
ULONG_PTR ReflectiveLoader( LPVOID lpAddr, LPVOID lpParameter );
#endif

#endif