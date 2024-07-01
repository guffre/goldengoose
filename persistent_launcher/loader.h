#ifndef _LOADLIBRARYR_H
#define _LOADLIBRARYR_H
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// we declare some common stuff in here...

#define DLL_METASPLOIT_ATTACH	4
#define DLL_METASPLOIT_DETACH	5
#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );
typedef BOOL (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

#define DLLEXPORT   __declspec( dllexport ) 

DWORD GetReflectiveLoaderOffset( VOID * lpReflectiveDllBuffer );

HANDLE WINAPI LoadRemoteLibraryR( HANDLE hProcess, LPVOID lpBuffer, DWORD dwLength, LPVOID lpParameter );

DWORD Rva2Offset( DWORD dwRva, UINT_PTR uiBaseAddress );

int inject( DWORD dwProcessId, LPVOID lpBuffer, DWORD dwLength );

//===============================================================================================//

#ifdef DEBUG
    #define dprintf(...) printf("DEBUG: " __VA_ARGS__)
#else
    #define dprintf(...) do {} while (0)
#endif

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d", e, GetLastError() ); break; }

#endif