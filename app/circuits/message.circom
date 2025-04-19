pragma circom 2.0.0;

template Message() {
    signal input thread_id;
    signal input user_id;
    signal input timestamp;
    signal input secret;
    signal output is_valid;

    // Verify user is in thread (simplified check)
    component thread_check = IsNonZero();
    thread_check.in <== thread_id;
    component user_check = IsNonZero();
    user_check.in <== user_id;

    // Ensure timestamp is recent (e.g., within 24 hours)
    signal current_time; // Assume provided by prover
    signal time_diff = timestamp - current_time;
    component time_valid = LessThan(64);
    time_valid.in[0] <== time_diff;
    time_valid.in[1] <== 86400; // 24 hours in seconds

    is_valid <== thread_check.out && user_check.out && time_valid.out;
}

component main {public [thread_id]} = Message();
