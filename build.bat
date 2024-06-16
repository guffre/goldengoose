cl.exe /LD screenshot.c common.c zlib/*.c cJSON/cJSON.c /Fo.\obj\ /O2 /Ot /GL
cl.exe /LD messageboxdll.c /Fo.\obj\ /O2 /Ot /GL
xxd -i messageboxdll.dll > messagebox.h
cl.exe -DWIN_X64 /MD main.c module_loader.c common.c /Fo.\obj\ /O2 /Ot /GL