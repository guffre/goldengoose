// cl.exe /LD /MD main.c /Fo.\obj\ /O2 /Ot /GL

#include <stdio.h>
#include <string.h>

#define CURL_STATICLIB
#include "tinycurl\include\curl\curl.h"

// Libraries needed for tinycurl
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "tinycurl\\lib\\libcurl_a.lib")

// This is for libcurl response data
struct MemoryStruct {
    char *response;
    size_t size;
};

// Callback function to handle libcurl response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *clientp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)clientp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if(ptr == NULL)
    {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

int main(void)
{
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.response = malloc(1);  // Allocate initial memory
    chunk.size = 0;             // No data initially

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1/key.pem");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "data=test");

        // Disable SSL certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Specify the callback function to handle the response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Perform the request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else {
            // Get the response code if needed
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            printf("Response code: %ld\n", response_code);

            // Now chunk.memory points to a memory block containing the full response
            printf("Response body: %s\n", chunk.response);
        }

        // Cleanup
        curl_easy_cleanup(curl);
        free(chunk.response);  // Free allocated memory for response
    }

    curl_global_cleanup();

    return 0;
}

__declspec(dllexport) void MainExport(void)
{
    main();
}
