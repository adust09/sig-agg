// Aggregation data model types for XMSS signature aggregation

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use serde::{Deserialize, Serialize};

// Type alias for the XMSS signature scheme we're using
type XMSSSignature = SIGWinternitzLifetime18W1;

/// Aggregation mode determining validation and verification logic
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationMode {
    /// All signatures share the same public key
    SingleKey,
    /// Signatures may have different public keys
    MultiKey,
}

/// Represents a single XMSS signature with verification context
#[derive(Serialize, Deserialize)]
pub struct VerificationItem {
    /// Message that was signed
    pub message: [u8; MESSAGE_LENGTH],
    /// Epoch (time period) when signature was created
    pub epoch: u32,
    /// XMSS signature data
    pub signature: <XMSSSignature as SignatureScheme>::Signature,
    /// Public key (optional - required for MultiKey mode, None for SingleKey)
    pub public_key: Option<<XMSSSignature as SignatureScheme>::PublicKey>,
}

/// Batch of signatures ready for aggregation
#[derive(Serialize, Deserialize)]
pub struct AggregationBatch {
    /// Aggregation mode for this batch
    pub mode: AggregationMode,
    /// Shared public key (SingleKey mode only)
    pub public_key: Option<<XMSSSignature as SignatureScheme>::PublicKey>,
    /// Collection of verification items
    pub items: Vec<VerificationItem>,
}

/// Metadata about proof generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Timestamp when proof was generated
    pub timestamp: u64,
    /// Batch size (number of signatures)
    pub batch_size: usize,
    /// zkVM configuration used
    pub memory_size: usize,
    pub trace_length: usize,
}

/// Aggregation proof (zkVM proof + metadata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationProof {
    /// Jolt zkVM proof bytes
    pub proof: Vec<u8>,
    /// Number of signatures verified in the proof
    pub verified_count: u32,
    /// Batch mode used during aggregation
    pub mode: AggregationMode,
    /// Proof generation metadata
    pub metadata: ProofMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashsig::signature::SignatureScheme;
    use std::sync::OnceLock;

    // Shared test keypair to avoid expensive key generation in each test
    static TEST_KEYPAIR: OnceLock<(
        <XMSSSignature as SignatureScheme>::PublicKey,
        <XMSSSignature as SignatureScheme>::SecretKey,
    )> = OnceLock::new();

    fn get_test_keypair() -> &'static (
        <XMSSSignature as SignatureScheme>::PublicKey,
        <XMSSSignature as SignatureScheme>::SecretKey,
    ) {
        TEST_KEYPAIR.get_or_init(|| {
            let mut rng = rand::rng();
            XMSSSignature::key_gen(&mut rng, 0, 20)
        })
    }

    #[test]
    fn test_aggregation_mode_equality() {
        assert_eq!(AggregationMode::SingleKey, AggregationMode::SingleKey);
        assert_eq!(AggregationMode::MultiKey, AggregationMode::MultiKey);
        assert_ne!(AggregationMode::SingleKey, AggregationMode::MultiKey);
    }

    #[test]
    fn test_aggregation_mode_copy() {
        let mode = AggregationMode::SingleKey;
        let mode_copy = mode;
        assert_eq!(mode, mode_copy);
    }

    #[test]
    fn test_verification_item_serde() {
        // Use shared test keypair
        let (pk, sk) = get_test_keypair();

        let message = [42u8; MESSAGE_LENGTH];
        let epoch = 5u32;
        let signature = XMSSSignature::sign(sk, epoch, &message)
            .expect("Signing should succeed");

        // Clone pk for the item
        let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
        let pk_clone = bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        let item = VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone),
        };

        // Test serialization
        let serialized = bincode::serialize(&item).expect("Serialization should succeed");

        // Test deserialization
        let deserialized: VerificationItem = bincode::deserialize(&serialized)
            .expect("Deserialization should succeed");

        // Verify fields match
        assert_eq!(deserialized.message, item.message);
        assert_eq!(deserialized.epoch, item.epoch);
        assert!(deserialized.public_key.is_some());
    }

    #[test]
    fn test_aggregation_batch_serde() {
        let (pk, sk) = get_test_keypair();

        let item1 = VerificationItem {
            message: [1u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(sk, 0, &[1u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: None,
        };

        let item2 = VerificationItem {
            message: [2u8; MESSAGE_LENGTH],
            epoch: 1,
            signature: XMSSSignature::sign(sk, 1, &[2u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: None,
        };

        // Clone pk for the batch
        let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
        let pk_clone = bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        let batch = AggregationBatch {
            mode: AggregationMode::SingleKey,
            public_key: Some(pk_clone),
            items: vec![item1, item2],
        };

        // Test serialization
        let serialized = bincode::serialize(&batch).expect("Serialization should succeed");

        // Test deserialization
        let deserialized: AggregationBatch = bincode::deserialize(&serialized)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized.mode, AggregationMode::SingleKey);
        assert!(deserialized.public_key.is_some());
        assert_eq!(deserialized.items.len(), 2);
    }

    #[test]
    fn test_aggregation_proof_serde() {
        let metadata = ProofMetadata {
            timestamp: 1234567890,
            batch_size: 100,
            memory_size: 10240,
            trace_length: 65536,
        };

        let proof = AggregationProof {
            proof: vec![1, 2, 3, 4, 5],
            verified_count: 100,
            mode: AggregationMode::MultiKey,
            metadata,
        };

        // Test serialization
        let serialized = bincode::serialize(&proof).expect("Serialization should succeed");

        // Test deserialization
        let deserialized: AggregationProof = bincode::deserialize(&serialized)
            .expect("Deserialization should succeed");

        assert_eq!(deserialized.proof, proof.proof);
        assert_eq!(deserialized.verified_count, 100);
        assert_eq!(deserialized.mode, AggregationMode::MultiKey);
        assert_eq!(deserialized.metadata.batch_size, 100);
    }

    #[test]
    fn test_verification_item_creation() {
        let (pk, sk) = get_test_keypair();

        let item = VerificationItem {
            message: [0u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(sk, 0, &[0u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: Some(bincode::deserialize(&bincode::serialize(pk).unwrap()).unwrap()),
        };

        // Verify item was created successfully
        assert_eq!(item.epoch, 0);
        assert!(item.public_key.is_some());
    }

    #[test]
    fn test_aggregation_batch_creation() {
        let (pk, sk) = get_test_keypair();

        let item = VerificationItem {
            message: [0u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(sk, 0, &[0u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: None,
        };

        let batch = AggregationBatch {
            mode: AggregationMode::SingleKey,
            public_key: Some(bincode::deserialize(&bincode::serialize(pk).unwrap()).unwrap()),
            items: vec![item],
        };

        assert_eq!(batch.mode, AggregationMode::SingleKey);
        assert_eq!(batch.items.len(), 1);
    }
}
