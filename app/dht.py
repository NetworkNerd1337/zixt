from kademlia.network import Server
import asyncio
import logging

async def discover_peers(bootstrap_nodes=None):
    server = Server()
    await server.listen(8468)
    if bootstrap_nodes:
        await server.bootstrap(bootstrap_nodes)
    logging.info("DHT peer discovery started")
    return server