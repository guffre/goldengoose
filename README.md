# Description
A tool to remotely monitor a Windows machine. The main controller will only provide a reverse shell, and additional functionality will be loaded as modules.

# To build:
```
git clone https://github.com/guffre/RemoteMonitoring.git
git submodule init
git submodule update

# Make sure the "obj" folder exists, otherwise you will get build errors
# From the Windows Native Tools Command Prompt:
cl.exe /LD -DDEBUG screenshot.c zlib/*.c cJSON/cJSON.c /Fo.\obj\ /O2 /Ot /GL

# To test:
rundll32 D:\path\to\RemoteMonitoring\screenshot.dll,TestModuleCommand
```

# TODOs and Notes

## common.h
DataBlobs:
    This is the structure that will be sent over the socket:
        typedef struct {
            unsigned char **buffers; // Array of pointers to data buffers
            unsigned long *sizes;    // Array of sizes of each buffer
            int count;               // Number of buffers
        } DataBlobs;
    
    All modules will convert a DataBlob into a json object, and then send that over the comms channel.
