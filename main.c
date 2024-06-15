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

int main(void)
{
    CURL *curl;
    CURLcode res;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "data=test");

        // Disable SSL certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            printf("Done sending data!\n");
        }

        // Cleanup
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();

    return 0;
}

__declspec(dllexport) void MainExport(void)
{
    main();
}
