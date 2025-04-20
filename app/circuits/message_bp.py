from bulletproofs import Bulletproof

class MessageCircuit:
    def __init__(self):
        self.bulletproof = Bulletproof()

    def generate_proof(self, thread_id, user_id, timestamp, secret):
        # Prove user_id is in thread and timestamp is recent
        public_inputs = {"thread_id": thread_id}
        private_inputs = {"user_id": user_id, "timestamp": timestamp, "secret": secret}
        proof = self.bulletproof.prove(
            statement="thread_id != 0 && user_id != 0 && (timestamp - current_time) < 86400",
            public_inputs=public_inputs,
            private_inputs=private_inputs
        )
        return proof, public_inputs

    def verify_proof(self, proof, public_inputs):
        return self.bulletproof.verify(proof, public_inputs)
