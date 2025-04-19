from kademlia.network import Server
import asyncio
import logging
import ssl
import socket
import os

class DTLSServer(Server):
    def __init__(self):
        super().__init__()
        cert_path = os.path.join(os.path.dirname(__file__), '../certs/server.crt')
        key_path = os.path.join(os.path.dirname(__file__), '../certs/server.key')
        self.context = ssl.SSLContext(ssl.PROTOCOL_DTLS_SERVER)
        self.context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')

    async def listen(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock = self.context.wrap_socket(sock, server_side=True)
        sock.bind(('0.0.0.0', port))
        await super().listen(port, socket=sock)

async def discover_peers(bootstrap_nodes=None):
    server = DTLSServer()
    await server.listen(8468)
    if bootstrap_nodes:
        await server.bootstrap(bootstrap_nodes)
    logging.info("DHT peer discovery started over DTLS")
    return server
