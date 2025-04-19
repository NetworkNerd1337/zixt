from app.crypto import Crypto
from app.dht import DTLSServer
import hashlib
import json
import time
import asyncio
import logging

logging.basicConfig(level=logging.INFO)

class Block:
    def __init__(self, index, previous_hash, timestamp, data, signature):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data  # Includes zkp_proof
        self.signature = signature
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "data": self.data
        }, sort_keys=True)
        return hashlib.sha3_256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.crypto = Crypto()
        self.chain = [self.create_genesis_block()]
        self.dht_server = DTLSServer()
        self.node_id = hashlib.sha3_256(str(time.time()).encode()).hexdigest()

    def create_genesis_block(self):
        data = {"message": "Genesis Block"}
        return Block(0, "0", time.time(), data, "")

    async def start_dht(self, bootstrap_nodes=None):
        await self.dht_server.listen(8468)
        if bootstrap_nodes:
            await self.dht_server.bootstrap(bootstrap_nodes)
        logging.info(f"DHT node started with ID: {self.node_id}")

    async def stop_dht(self):
        self.dht_server.stop()

    def add_block(self, data, private_key):
        previous_block = self.chain[-1]
        index = previous_block.index + 1
        timestamp = time.time()
        block_string = json.dumps({"index": index, "previous_hash": previous_block.hash, "timestamp": timestamp, "data": data}, sort_keys=True)
        signature = self.crypto.sig.sign(block_string.encode(), private_key)
        new_block = Block(index, previous_block.hash, timestamp, data, signature)
        self.chain.append(new_block)
        asyncio.create_task(self.propagate_block(new_block))
        return new_block

    async def propagate_block(self, block):
        block_data = json.dumps({
            "index": block.index,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "data": block.data,
            "signature": block.signature,
            "hash": block.hash
        })
        await self.dht_server.set(f"block_{block.index}", block_data)
