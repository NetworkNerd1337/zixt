from kademlia.network import Server
import asyncio
import logging
import ssl
import socket
import os
import json

class DTLSServer(Server):
    def __init__(self):
        super().__init__()
        cert_path = os.path.join(os.path.dirname(__file__), '../certs/server.crt')
        key_path = os.path.join(os.path.dirname(__file__), '../certs/server.key')
        self.context = ssl.SSLContext(ssl.PROTOCOL_DTLS_SERVER)
        self.context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self.context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
        self.message_handlers = {
            "pre_prepare": self.handle_pre_prepare,
            "prepare": self.handle_prepare,
            "commit": self.handle_commit
        }

    async def listen(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock = self.context.wrap_socket(sock, server_side=True)
        sock.bind(('0.0.0.0', port))
        await super().listen(port, socket=sock)
        asyncio.create_task(self.handle_messages())

    async def handle_messages(self):
        while True:
            for key in await self.get_keys("pre_prepare_*"):
                message = await self.get(key)
                if message:
                    await self.message_handlers["pre_prepare"](json.loads(message))
            for key in await self.get_keys("prepare_*"):
                message = await self.get(key)
                if message:
                    await self.message_handlers["prepare"](json.loads(message))
            for key in await self.get_keys("commit_*"):
                message = await self.get(key)
                if message:
                    await self.message_handlers["commit"](json.loads(message))
            await asyncio.sleep(1)

    async def handle_pre_prepare(self, message):
        from app.blockchain import Blockchain
        blockchain = Blockchain()
        await blockchain.handle_pre_prepare(message)

    async def handle_prepare(self, message):
        from app.blockchain import Blockchain
        blockchain = Blockchain()
        await blockchain.handle_prepare(message)

    async def handle_commit(self, message):
        from app.blockchain import Blockchain
        blockchain = Blockchain()
        await blockchain.handle_commit(message)

async def discover_peers(bootstrap_nodes=None):
    server = DTLSServer()
    await server.listen(8468)
    if bootstrap_nodes:
        await server.bootstrap(bootstrap_nodes)
    logging.info("DHT peer discovery started over DTLS")
    return server
