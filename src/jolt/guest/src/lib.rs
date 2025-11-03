use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use serde::{Deserialize, Serialize};

// The signature scheme we are going to benchmark.
type XMSSSignature = SIGWinternitzLifetime18W1;

/// Aggregation mode determining validation and verification logic
#[derive(Serialize, Deserialize)]
pub enum AggregationMode {
    /// All signatures share the same public key
    SingleKey,
    /// Signatures may have different public keys
    MultiKey,
}

/// A single XMSS verification item.
#[derive(Serialize, Deserialize)]
pub struct VerificationItem {
    pub message: [u8; MESSAGE_LENGTH],
    pub epoch: u32,
    pub signature: <XMSSSignature as SignatureScheme>::Signature,
    /// Public key (optional - required for MultiKey mode, None for SingleKey)
    pub public_key: Option<<XMSSSignature as SignatureScheme>::PublicKey>,
}

/// The aggregation batch for zkVM verification
#[derive(Serialize, Deserialize)]
pub struct AggregationBatch {
    /// Aggregation mode for this batch
    pub mode: AggregationMode,
    /// Shared public key (SingleKey mode only)
    pub public_key: Option<<XMSSSignature as SignatureScheme>::PublicKey>,
    /// Collection of verification items
    pub items: Vec<VerificationItem>,
}

/// Verify aggregated signature batch in zkVM
///
/// This function verifies all signatures in the batch according to the aggregation mode:
/// - SingleKey: Uses shared public key from batch
/// - MultiKey: Uses per-item public keys
///
/// Returns the count of successfully verified signatures
#[jolt::provable(memory_size = 10240, max_trace_length = 65536)]
fn verify_aggregation(batch: AggregationBatch) -> u32 {
    let mut verified_count: u32 = 0;

    for item in batch.items {
        let is_valid = match batch.mode {
            AggregationMode::SingleKey => {
                // Single key: use shared public key from batch
                if let Some(ref pk) = batch.public_key {
                    SIGWinternitzLifetime18W1::verify(
                        pk,
                        item.epoch,
                        &item.message,
                        &item.signature,
                    )
                } else {
                    // SingleKey mode requires public_key
                    false
                }
            }
            AggregationMode::MultiKey => {
                // Multi-key: use item-specific public key
                if let Some(ref pk) = item.public_key {
                    SIGWinternitzLifetime18W1::verify(
                        pk,
                        item.epoch,
                        &item.message,
                        &item.signature,
                    )
                } else {
                    // MultiKey mode requires per-item public_key
                    false
                }
            }
        };

        if is_valid {
            verified_count += 1;
        }
    }

    verified_count
}
