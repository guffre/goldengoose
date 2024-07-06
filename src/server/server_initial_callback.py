# For initial callbacks via DNS
import time
from dnslib import QTYPE,RR,A,CNAME
from dnslib.server import DNSServer, BaseResolver, DNSLogger

# The port for GOLDENGOOSE clients to connect to
C2_LISTEN_ADDR = "127.0.0.1"
C2_LISTEN_PORT = 443

class CustomResolver(BaseResolver):
    def __init__(self, a_record, cname_record):
        self.a_record = a_record
        self.cname_record = cname_record
    
    def resolve(self, request, handler):
        global C2_LISTEN_PORT
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        #pdb.set_trace()
    
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.a_record), ttl=C2_LISTEN_PORT))
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(self.cname_record), ttl=60))
        elif qtype == QTYPE.CNAME:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(self.cname_record), ttl=60))
    
        return reply

def dns_server(a_record, cname_record, listen_address="0.0.0.0"):
    resolver = CustomResolver(a_record, cname_record)
    logger = DNSLogger()

    server = DNSServer(resolver, port=53, address=listen_address, logger=logger)
    server.start_thread()

if __name__ == '__main__':
    print("[+] Starting GOLDENGOOSE Initial Callback Server")
    dns_server(C2_LISTEN_ADDR, "WOWZERZ")
    print("[+] DNS Server listening on:")
    print("[+]      IPv4: 0.0.0.0")
    print("[+]      Port: UDP 53")
    print("[+] listening for connections...")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(f"Unhandled exception: {e}")