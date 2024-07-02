cl.exe /LD -DWIN_X64 messagebox_r.c
xxd -i messagebox_r.dll > messagebox_r.h
cl.exe -DWIN_X64 -DDEBUG loader.c