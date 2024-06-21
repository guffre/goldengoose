# Description
A tool to remotely monitor a Windows machine. The main controller will only provide a reverse shell, and additional functionality will be loaded as modules.

# To build:

Set up the repo and submodule dependencies:
```
git clone https://github.com/guffre/RemoteMonitoring.git
cd RemoteMonitoring
git submodule init
git submodule update
```

Then build!
```
build.bat
```

# Build details

## tiny-curl
I link against tiny-curl. If you want to build your own lib, great! Here's how:
I include these instructions because tinycurl has a bug which prevents it from compiling (Windows specific?)
```
# From the Windows Native Tools Command Prompt:
# If you don't want to use the tinycurl lib that I included, you can build it yourself:
cd curl
buildconf.bat
cd winbuild
nmake /f Makefile.vc mode=static ENABLE_IPV6=no MACHINE=x64 DEBUG=no WITH_PREFIX=tinycurl
mv tinycurl ../../

# IMPORTANT NOTE!!! There is a bug in tiny-curl when compiling. You will get this error:
# error C2061: syntax error: identifier 'curl_fd_set'
# This is a bug with tiny-curl, not with this project. You need to edit the system.h file
# This line: typedef fd_set curl_fd_set;
# Should be: typedef struct fd_set curl_fd_set;
```

## To build the main executable (dll):
cl.exe -DWIN_X64 /LD /MD main.c gadget_loader.c common.c base64.c /Fo.\obj\ /O2 /Ot /GL

## To build the main executable (exe) with debug statements:
cl.exe -DWIN_X64 -DDEBUG /LD /MD main.c gadget_loader.c common.c base64.c /Fo.\obj\ /O2 /Ot /GL

## To test:
Just use the included `controller\server.py` to communicate to goldengoose

## Alternate test:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl s_server -cert cert.pem -key key.pem -accept 443
rundll32 D:\path\to\goldengoose\main.dll,MainExport

## To build a test screenshot gadget:
cl.exe -DDEBUG /I"." /LD gadgets/screenshot.c common.c base64.c zlib/*.c cJSON/cJSON.c /Fo.\obj\ /O2 /Ot /GL

## To test the screenshot gadget:
rundll32 D:\path\to\goldengoose\screenshot.dll,TestGadget
### This will create a file `D:\bitmap.json` if successful. If you don't have a D: then edit the code
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
    
