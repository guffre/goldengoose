# GOLDENGOOSE

## Overview

This repository contains a Command and Control (C2) framework implemented in C, designed for managing and executing commands on remote systems. The framework utilizes a client-server model where commands are issued by a server and executed on the client system. All communications go over encrypted HTTPS. The server is written in Python, and is known to work on 3.8+. Initial callbacks are communicated over legitimate DNS, with the Stager and C2 running on a different protocol (HTTPS). These can all be the same server, or different servers.

![image](https://github.com/guffre/goldengoose/assets/21281361/e04b6229-e60d-4753-a882-90b8fcb3d131)

## Cool Features

- **No RWX in Reflective Loader**: The Reflective DLL Loader has been modified to avoid marking memory as Read-Write-Execute (RWX), a common signature often flagged by PSPs.
- **Normal HTTPS Dataflow**: The client initiates requests to the server and awaits responses. This approach diverges from traditional C2 frameworks, which typically have servers initiate requests with clients responding.
- **Multi-stage Loading**: The included `launcher.exe` can be installed as a persistent mechanism on a machine. This will callback to a DNS server, which redirects to a staging server that supplies the payload code.
- **Initial Callback Handler**: Initial callbacks are handled by a separate executable. This means if the client were to ever crash, you don't lose access.
- **Initial Callback via DNS**: Uses DNS legitimately, not as a covert channel for comms. You can use the supplied DNS server (in `server_initial_callback.py`) to respond to DNS, or you can setup a legitimate domain and register it. The IPv4 address returned is the stager server, and the TTL is the stager port.

## Features

- **Command Execution**: Execute commands on the client
- **Shell Interaction**: Coming soon! Currently displays message boxes on the client system.
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

Build the goldengoose client:
```
cd src/client
build.bat
```

Build the launcher:
```
cd src/launcher
build.bat
```

Requirements for the server:
```
pip install dnslib
```

## Usage

The server requires a `cert.pem` and `key.pem`. You can use the included self-signed ones, but if you want to create your own the `openssl` command is detailed in the "Test and Debug" section.

Three servers are included:

1. `server_initial_callback.py` will catch initial callbacks (dns request, dns reply) and provide the staging server information.
2. `server_stager.py` will supply payloads that `launcher.exe` will then inject into another processes memory.
3. `server_c2.py` is used for command and control of the actual client.

Of note: You can host these all on the same server, or place them across three machines. Dealers choice.

To run:
```
py -3 server_c2.py
```

To run the client directly:
```
main.exe
rundll32 main.dll,MainExport
```

To run the persistent loader version:
```
launcher.exe
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
