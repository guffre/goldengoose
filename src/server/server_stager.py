import contextlib
import socket
import ssl
from http.server import *
import http.server

SHARED_DIRECTORY = '.'
STAGER_LISTENER_PORT = 443

handler_class = SimpleHTTPRequestHandler

class DualStackServer(ThreadingHTTPServer):
    def server_bind(self):
        # suppress exception when protocol is IPv4
        with contextlib.suppress(Exception):
            self.socket.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        ret = super().server_bind()
        # Lets enable SSL for encryption!
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("cert.pem",keyfile="key.pem")
        self.socket = context.wrap_socket(sock=self.socket, server_side=True)
        return ret
    
    def finish_request(self, request, client_address):
        self.RequestHandlerClass(request, client_address, self, directory=SHARED_DIRECTORY)

if __name__ == '__main__':
    http.server.test(
        HandlerClass=handler_class,
        ServerClass=DualStackServer,
        port=STAGER_LISTENER_PORT,
        bind="0.0.0.0",
        protocol="HTTP/1.1",
    )