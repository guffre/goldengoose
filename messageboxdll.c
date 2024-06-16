// cl.exe /LD messageboxdll.c /Fo.\obj\ /O2 /Ot /GL
#include <windows.h>
#pragma comment(lib, "user32.lib") 

// Function that shows a message box
__declspec(dllexport) void ShowMessageBox() {
    MessageBox(NULL, "Hello from DLL!", "DLL Message", MB_ICONINFORMATION);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    MessageBox(NULL, "DLL Loaded!", "DLL Loaded!", MB_ICONINFORMATION);
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // DLL is being loaded
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