# Description
A tool to remotely monitor a Windows machine. The main controller will only provide a reverse shell, and additional functionality will be loaded as modules.

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
