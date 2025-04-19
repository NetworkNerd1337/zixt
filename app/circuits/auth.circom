pragma circom 2.0.0;

template Auth() {
    signal input user_id;
    signal input public_key_hash;
    signal input secret;
    signal output is_valid;

    // Hash the secret (e.g., SPHINCS+ private key) with SHA3-512
    component hasher = Sha3_512();
    hasher.in <== secret;
    assert(hasher.out == public_key_hash);

    // Ensure user_id is non-zero (valid user)
    is_valid <== user_id != 0;
}

component main {public [public_key_hash]} = Auth();
