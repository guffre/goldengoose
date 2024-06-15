# Description
A tool to remotely monitor a Windows machine. The main controller will only provide a reverse shell, and additional functionality will be loaded as modules.

# To build:
```
git clone https://github.com/guffre/RemoteMonitoring.git
cd RemoteMonitoring
git submodule init
git submodule update

# From the Windows Native Tools Command Prompt:
# If you don't want to use the tinycurl lib that I included, you can build it yourself:
cd curl
buildconf.bat
cd winbuild
nmake /f Makefile.vc mode=static ENABLE_IPV6=no MACHINE=x64 DEBUG=no WITH_PREFIX=tinycurl
mv tinycurl ../../

# IMPORTANT NOTE!!! There is a bug in tiny-curl when compiling. You will get this error:
# error C2061: syntax error: identifier 'curl_fd_set'
# This is apparently a bug with tiny-curl. You need to edit the system.h file
# This line: typedef fd_set curl_fd_set;
# Should be: typedef struct fd_set curl_fd_set;

# To build the main executable (dll):
cl.exe /LD /MD main.c /Fo.\obj\ /O2 /Ot /GL

# To test:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl s_server -cert cert.pem -key key.pem -accept 443
rundll32 D:\path\to\RemoteMonitoring\main.dll,MainExport

# To build the screenshot module:
cl.exe /LD -DDEBUG screenshot.c zlib/*.c cJSON/cJSON.c /Fo.\obj\ /O2 /Ot /GL

# To test the screenshot module:
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
