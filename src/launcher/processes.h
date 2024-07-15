#ifndef _PROCESSES_H
#define _PROCESSES_H

#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <Psapi.h>

#pragma comment(lib, "advapi32.lib")

// debug print statements
#ifdef DEBUG
    #define dprintf(...) printf(__VA_ARGS__);
#else
    #define dprintf(...) do {} while (0);
#endif

DWORD GetInjectProcess(void);
BOOL GetProcessModule(DWORD processID, char* moduleName);
void ListProcessModules(DWORD processID);
void ListProcessThreads(DWORD processID);
void ListProcessPrivileges(HANDLE hProcess);
LPWSTR GetProcessUserToken(HANDLE hProcess);
BOOL SetPriv(HANDLE token, char *privilege);


#endif