// cl.exe /LD messageboxdll.c /Fo.\obj\ /O2 /Ot /GL
#include <windows.h>
#pragma comment(lib, "user32.lib") 

typedef void (*DllFunctionPointer)(char*);

// Function that shows a message box
__declspec(dllexport) void ShowMessageBox(char* args) {
    MessageBox(NULL, args, args, MB_ICONINFORMATION);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    MessageBox(NULL, "DLL Loaded!", "DLL Loaded!", MB_ICONINFORMATION);
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
            if( lpReserved != NULL )
            {
                MessageBox(NULL, "Setting lpReserved!", "d", MB_ICONINFORMATION);
				// *(HMODULE *)lpReserved = ShowMessageBox;
                *(DllFunctionPointer*)lpReserved = ShowMessageBox;
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