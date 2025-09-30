use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use serde::{Deserialize, Serialize};

// The signature scheme we are going to benchmark.
type BenchmarkedSignature = SIGWinternitzLifetime18W1;

/// A single XMSS verification item.
#[derive(Serialize, Deserialize)]
pub struct VerificationItem {
    pub message: [u8; MESSAGE_LENGTH],
    pub epoch: u32,
    pub signature: <BenchmarkedSignature as SignatureScheme>::Signature,
}

/// The entire batch of data the guest program will receive.
#[derive(Serialize, Deserialize)]
pub struct VerificationBatch {
    pub public_key: <BenchmarkedSignature as SignatureScheme>::PublicKey,
    pub items: Vec<VerificationItem>,
}

#[jolt::provable(memory_size = 10240, max_trace_length = 65536)]
fn verify_signatures(batch: VerificationBatch) -> u32 {
    let mut verified_count: u32 = 0;
    for item in batch.items {
        let is_valid = SIGWinternitzLifetime18W1::verify(
            &batch.public_key,
            item.epoch,
            &item.message,
            &item.signature,
        );

        if is_valid {
            verified_count += 1;
        }
    }
    verified_count
}
