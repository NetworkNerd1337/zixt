from bulletproofs import Bulletproof

class AuthCircuit:
    def __init__(self):
        self.bulletproof = Bulletproof()

    def generate_proof(self, user_id, public_key_hash, secret):
        # Prove user_id is non-zero and secret hashes to public_key_hash
        public_inputs = {"public_key_hash": public_key_hash}
        private_inputs = {"user_id": user_id, "secret": secret}
        proof = self.bulletproof.prove(
            statement="user_id != 0 && sha3_512(secret) == public_key_hash",
            public_inputs=public_inputs,
            private_inputs=private_inputs
        )
        return proof, public_inputs

    def verify_proof(self, proof, public_inputs):
        return self.bulletproof.verify(proof, public_inputs)
