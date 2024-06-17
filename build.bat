cl.exe /LD screenshot.c common.c base64.c zlib/*.c cJSON/cJSON.c /Fo.\obj\ /O2 /Ot /GL
cl.exe /LD messageboxdll.c /Fo.\obj\ /O2 /Ot /GL
xxd -i messageboxdll.dll > messagebox.h
xxd -i screenshot.dll > screenshot.h
cl.exe -DWIN_X64 /MD main.c module_loader.c common.c base64.c /Fo.\obj\ /O2 /Ot /GL
cl.exe -DWIN_X64 /LD /MD main.c module_loader.c common.c base64.c /Fo.\obj\ /O2 /Ot /GL
del *.exp
del *.lib