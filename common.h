#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>

// Base64 dictionary
static const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

typedef struct {
    unsigned char **buffers; // Array of pointers to the compressed data buffers
    unsigned long *sizes;   // Array of sizes of each compressed buffer
    int count;      // Number of buffers (number of monitors)
} DataBlobs;

int Base64Encode(const unsigned char* buffer, int length, char* base64Buffer);
void FreeBlobs(DataBlobs* data);

#ifdef _WIN32
#include <Windows.h>
ULONG_PTR ReflectiveLoader( LPVOID lpAddr, LPVOID lpParameter );
#endif

#endif