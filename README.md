# GOLDENGOOSE

## Overview

This repository contains a Command and Control (C2) framework implemented in C, designed for managing and executing commands on remote systems. The framework utilizes a client-server model where commands are issued by a server and executed on the client system. All communications go over encrypted HTTPS. The server is written in Python, and is known to work on 3.8+. Initial callbacks are communicated over legitimate DNS, with C2 running on a different protocol.

## Cool Features

- **No RWX in Reflective Loader**: The Reflective DLL Loader has been modified to avoid marking memory as Read-Write-Execute (RWX), a common signature often flagged by PSPs.
- **Normal HTTPS Dataflow**: The client initiates requests to the server and awaits responses. This approach diverges from traditional C2 frameworks, which typically have servers initiate requests with clients responding.
- **Initial Callback Handler**: Initial callbacks are handled by a separate executable. This means if the client were to ever crash, you don't lose access.
- **Initial Callback via DNS**: This is using DNS in a legitimate way, not as a covert channel for comms. You can use the supplied DNS server (in `server.py`) to respond to DNS, or you can setup a legitimate domain and register it. The IPv4 address returned is the actual C2 server, and the TTL is the C2 port.

## Features

- **Command Execution**: Execute commands on the client
- **Shell Interaction**: Display message boxes on the client system (Windows-specific).
- **Dynamic Code Loading**: Load and execute dynamically generated code (gadgets) received from the server.
- **Installation Logging**: Log installation status by creating a file (`installed.txt`) on the client system.
- **Encrypted Communications**: All communications are HTTPS only. Additional channels may be added in the future.

## Installation

Set up the repo and submodule dependencies:
```
git clone https://github.com/guffre/goldengoose.git
cd goldengoose
git submodule init
git submodule update
```

Then build!
```
build.bat
```

Requirements for the server:
```
pip install dnslib
```

## Usage

The server requires a `cert.pem` and `key.pem`. You can use the included self-signed ones, but if you want to create your own the `openssl` command is detailed in the "Test and Debug" section.

The server will catch both initial callbacks (dns request, dns reply)
as well as provide C2 over clients.

To run:
```
py -3 server.py
```

The client (currently) has no setup. Just run it:
```
main.exe
rundll32 main.dll,MainExport
```

## Detailed Compilation

### tiny-curl
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

### Test and Debug
```
# To build the main executable (dll):
cl.exe -DWIN_X64 /LD /MD main.c gadget_loader.c common.c base64.c /Fo.\obj\ /O2 /Ot /GL

# To build the main executable (exe) with debug statements:
cl.exe -DWIN_X64 -DDEBUG /LD /MD main.c gadget_loader.c common.c base64.c /Fo.\obj\ /O2 /Ot /GL

# To test:
Just use the included `controller\server.py` to communicate to goldengoose

# Alternate test:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
openssl s_server -cert cert.pem -key key.pem -accept 443
rundll32 D:\path\to\goldengoose\main.dll,MainExport

# To build a test screenshot gadget:
cl.exe -DDEBUG /I"." /LD gadgets/screenshot.c common.c base64.c zlib/*.c cJSON/cJSON.c /Fo.\obj\ /O2 /Ot /GL

# To test the screenshot gadget:
rundll32 D:\path\to\goldengoose\screenshot.dll,TestGadget
### This will create a file `D:\bitmap.json` if successful. If you don't have a D: then edit the code
```