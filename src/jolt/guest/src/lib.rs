use hashsig::{
    signature::{
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
        SignatureScheme,
    },
    MESSAGE_LENGTH,
};
use serde::{Deserialize, Serialize};

// The signature scheme we are going to benchmark.
type XMSSSignature = SIGWinternitzLifetime18W1;

/// A single XMSS verification item.
///
/// Each item contains its own public key, supporting multi-key aggregation.
#[derive(Serialize, Deserialize)]
pub struct VerificationItem {
    pub message: [u8; MESSAGE_LENGTH],
    pub epoch: u32,
    pub signature: <XMSSSignature as SignatureScheme>::Signature,
    /// Public key for this signature (required)
    pub public_key: <XMSSSignature as SignatureScheme>::PublicKey,
}

/// The aggregation batch for zkVM verification
///
/// Each item in the batch includes its own public key, allowing
/// signatures from different keys to be aggregated together.
#[derive(Serialize, Deserialize)]
pub struct AggregationBatch {
    /// Collection of verification items (each with its own public key)
    pub items: Vec<VerificationItem>,
}

/// Verify aggregated signature batch in zkVM
///
/// This function verifies all signatures in the batch, where each signature
/// includes its own public key. This enables multi-key aggregation where
/// signatures from different keys can be batched together.
///
/// Returns the count of successfully verified signatures
// Resource hints stay power-of-two sized but far tighter than the previous defaults.
// Keeping memory_size down prevents Dory from allocating multi-GB prover polynomials.
#[jolt::provable(
    stack_size = 32_768,
    memory_size = 8_388_608,
    max_input_size = 4_194_304,
    max_trace_length = 33_554_432
)]
fn verify_aggregation(batch: AggregationBatch) -> u32 {
    let mut verified_count: u32 = 0;

    for item in batch.items {
        // Each item has its own public key
        let is_valid = SIGWinternitzLifetime18W1::verify(
            &item.public_key,
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
