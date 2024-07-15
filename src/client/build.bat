:: Build screenshot.dll
cl.exe /I"." /LD gadgets/screenshot.c common.c base64.c commandnode.c linkedlist.c ../../zlib/*.c ../../cJSON/cJSON.c /Fo..\..\obj\ /O2 /Ot /GL

:: These were used for testing, saving for posterity
:: cl.exe /LD messageboxdll.c /Fo.\obj\ /O2 /Ot /GL
:: xxd -i messageboxdll.dll > messagebox.h
:: xxd -i screenshot.dll > screenshot.h

:: Debug build of the client as .exe
cl.exe -DWIN_X64 -DDEBUG /MD main.c gadget_loader.c common.c base64.c commandnode.c linkedlist.c /Fo..\..\obj\ /O2 /Ot /GL

:: Non-debug build of the client as .dll
cl.exe -DWIN_X64 /LD /MD main.c gadget_loader.c common.c base64.c commandnode.c linkedlist.c /Fo..\..\obj\ /O2 /Ot /GL

:: Copy main.dll into the server folder. TODO: WOWZERZ should be dynamic
copy main.dll ..\server\WOWZERZ

:: Cleanup some junk files
del *.exp *.lib
