#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>

#ifdef DEBUG
    #define debugf(...) printf("DEBUG: " __VA_ARGS__)
#else
    #define debugf(...) do {} while (0)
#endif

#define SAFE_FREE(x) do {if (x) { free(x); x=NULL;}} while(0)

// Not sure if this will be common or just for screenshots
typedef struct {
    unsigned char **buffers; // Array of pointers to the compressed data buffers
    unsigned long *sizes;    // Array of sizes of each compressed buffer
    unsigned int count;      // Number of buffers (number of monitors)
} DataBlobs;

// For libcurl response data
struct MemoryStruct {
    char *memory;
    size_t size;
};

void FreeBlobs(DataBlobs* data);

#ifdef _WIN32
#include <Windows.h>
ULONG_PTR ReflectiveLoader( LPVOID lpAddr, LPVOID lpParameter );
#endif

#endif