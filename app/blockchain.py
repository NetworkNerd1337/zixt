from app.crypto import Crypto
from app.dht import DTLSServer
import hashlib
import json
import time
import asyncio
import logging
from collections import defaultdict

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
        self.nodes = {}  # {node_id: (ip, port, public_key)}
        self.pending_blocks = {}  # {block_hash: block}
        self.prepare_votes = defaultdict(set)  # {block_hash: set(node_ids)}
        self.commit_votes = defaultdict(set)  # {block_hash: set(node_ids)}
        self.fault_tolerance = 1  # f, where N >= 3f + 1
        self.rotation_interval = 10  # Rotate primary every 10 blocks

    def create_genesis_block(self):
        data = {"message": "Genesis Block"}
        return Block(0, "0", time.time(), data, "")

    async def start_dht(self, bootstrap_nodes=None):
        await self.dht_server.listen(8468)
        if bootstrap_nodes:
            await self.dht_server.bootstrap(bootstrap_nodes)
        logging.info(f"DHT node started with ID: {self.node_id}")
        # Register node with public key
        await self.dht_server.set(f"node_{self.node_id}", json.dumps({
            "ip": "0.0.0.0",  # Local binding, resolved by DHT
            "port": 8468,
            "public_key": base64.b64encode(self.crypto.sig.generate_keypair()).decode()
        }))
        # Fetch known nodes
        await self.update_nodes()

    async def stop_dht(self):
        self.dht_server.stop()

    async def update_nodes(self):
        nodes = {}
        for node_id in await self.dht_server.get_keys("node_*"):
            node_data = await self.dht_server.get(node_id)
            if node_data:
                data = json.loads(node_data)
                nodes[node_id] = (data["ip"], data["port"], base64.b64decode(data["public_key"]))
        self.nodes = nodes
        self.fault_tolerance = (len(self.nodes) - 1) // 3  # f = (N-1)/3

    def get_primary_node(self, block_index):
        node_ids = sorted(self.nodes.keys())
        if not node_ids:
            return self.node_id
        return node_ids[(block_index // self.rotation_interval) % len(node_ids)]

    async def add_block(self, data, private_key):
        previous_block = self.chain[-1]
        index = previous_block.index + 1
        timestamp = time.time()
        block_string = json.dumps({"index": index, "previous_hash": previous_block.hash, "timestamp": timestamp, "data": data}, sort_keys=True)
        signature = self.crypto.sig.sign(block_string.encode(), private_key)
        new_block = Block(index, previous_block.hash, timestamp, data, signature)
        
        if self.get_primary_node(index) == self.node_id:
            await self.propose_block(new_block)
        else:
            self.pending_blocks[new_block.hash] = new_block
            await self.dht_server.set(f"block_proposal_{new_block.hash}", json.dumps({
                "block": {
                    "index": new_block.index,
                    "previous_hash": new_block.previous_hash,
                    "timestamp": new_block.timestamp,
                    "data": new_block.data,
                    "signature": base64.b64encode(new_block.signature).decode(),
                    "hash": new_block.hash
                },
                "proposer": self.node_id
            }))
        return new_block

    async def propose_block(self, block):
        self.pending_blocks[block.hash] = block
        await self.dht_server.set(f"pre_prepare_{block.hash}", json.dumps({
            "block_hash": block.hash,
            "block": {
                "index": block.index,
                "previous_hash": block.previous_hash,
                "timestamp": block.timestamp,
                "data": block.data,
                "signature": base64.b64encode(block.signature).decode(),
                "hash": block.hash
            },
            "primary": self.node_id
        }))

    async def handle_pre_prepare(self, message):
        block_hash = message["block_hash"]
        block_data = message["block"]
        block = Block(
            block_data["index"],
            block_data["previous_hash"],
            block_data["timestamp"],
            block_data["data"],
            base64.b64decode(block_data["signature"])
        )
        if block.hash != block_hash or block.index != self.chain[-1].index + 1:
            return
        if not self.crypto.verify_user(block_data["data"]["sender_public_key"], block.signature, json.dumps(block_data["data"], sort_keys=True).encode()):
            return
        self.pending_blocks[block_hash] = block
        await self.dht_server.set(f"prepare_{block_hash}_{self.node_id}", json.dumps({
            "block_hash": block_hash,
            "node_id": self.node_id
        }))
        self.prepare_votes[block_hash].add(self.node_id)

    async def handle_prepare(self, message):
        block_hash = message["block_hash"]
        node_id = message["node_id"]
        if block_hash in self.pending_blocks and node_id in self.nodes:
            self.prepare_votes[block_hash].add(node_id)
            if len(self.prepare_votes[block_hash]) >= 2 * self.fault_tolerance + 1:
                await self.dht_server.set(f"commit_{block_hash}_{self.node_id}", json.dumps({
                    "block_hash": block_hash,
                    "node_id": self.node_id
                }))
                self.commit_votes[block_hash].add(self.node_id)

    async def handle_commit(self, message):
        block_hash = message["block_hash"]
        node_id = message["node_id"]
        if block_hash in self.pending_blocks and node_id in self.nodes:
            self.commit_votes[block_hash].add(node_id)
            if len(self.commit_votes[block_hash]) >= 2 * self.fault_tolerance + 1:
                block = self.pending_blocks[block_hash]
                self.chain.append(block)
                del self.pending_blocks[block_hash]
                self.prepare_votes[block_hash].clear()
                self.commit_votes[block_hash].clear()
                logging.info(f"Block {block.index} committed to chain")
                await self.propagate_block(block)

    async def propagate_block(self, block):
        block_data = json.dumps({
            "index": block.index,
            "previous_hash": block.previous_hash,
            "timestamp": block.timestamp,
            "data": block.data,
            "signature": base64.b64encode(block.signature).decode(),
            "hash": block.hash
        })
        await self.dht_server.set(f"block_{block.index}", block_data)
