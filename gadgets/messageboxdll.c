// From directory above this file:
// cl.exe /I"." /LD gadgets/messageboxdll.c /Fo.\obj\ /O2 /Ot /GL

#include <windows.h>
#include "commandlist.h"
#pragma comment(lib, "user32.lib") 

typedef void (*DllFunctionPointer)(char*);
typedef CommandNode* (*CommandNodePointer)(void);
CommandNode* ModuleCommand;


// Function that shows a message box
__declspec(dllexport) char* ShowMessageBox(char* args)
{
    MessageBox(NULL, args, args, MB_ICONINFORMATION);
    printf("Test: %s\n", args);
    return NULL;
}

__declspec(dllexport) CommandNode* GetModuleCommand(void)
{
    ModuleCommand = createCommandNode("messagebox", ShowMessageBox);
    return ModuleCommand;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    MessageBox(NULL, "DLL Loaded!", "DLL Loaded!", MB_ICONINFORMATION);
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
            if( lpReserved != NULL )
            {
                MessageBox(NULL, "Setting lpReserved!", "d", MB_ICONINFORMATION);
                *(CommandNodePointer*)lpReserved = GetModuleCommand;

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