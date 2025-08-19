#include <stdio.h>
#include <windows.h>
#include <windns.h>

#pragma comment(lib, "dnsapi.lib")

typedef struct _DNS_CACHE_ENTRY {
    struct _DNS_CACHE_ENTRY* pNext;        // Pointer to next entry
    PWSTR                    pszName;      // DNS Record Name
    WORD                     wType;        // DNS Record Type
    WORD                     wDataLength;  // Not referenced
    DWORD                    dwFlags;      // DNS Record Flags
    DWORD                    dwTtl;        // DNS Time-to-live
} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;

// Function to print the DNS cache
void PrintDnsCache() {
    PDNS_CACHE_ENTRY pEntry = NULL;
    PDNS_CACHE_ENTRY pCurrent = NULL;

    // Get the first cache entry
    pEntry = (PDNS_CACHE_ENTRY)malloc(sizeof(DNS_CACHE_ENTRY));
    if (!pEntry) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    DnsGetCacheDataTable(pEntry);
    pCurrent = pEntry->pNext;
    while (pCurrent) {
        printf("Entry:\n");
        printf("  Name: %S\n", pCurrent->pszName);
        printf("  Type: %u\n", pCurrent->wType);
        printf("  Data Length: %u\n", pCurrent->wDataLength);
        printf("  Flags: %u\n", pCurrent->dwFlags);
        printf("  TTL: %u\n", pCurrent->dwTtl);

        pCurrent = pCurrent->pNext;
    }

    // Free the allocated buffer
    free(pEntry);
}

int main() {
    PrintDnsCache();
    return 0;
}