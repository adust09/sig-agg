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

/// Aggregation mode determining validation and verification logic.
///
/// This enum specifies how signatures should be validated and verified within
/// a batch. The mode affects both validation rules and zkVM verification logic.
///
/// # Variants
///
/// ## `SingleKey`
///
/// All signatures in the batch share the same XMSS public key. Each signature
/// must use a unique epoch to prevent signature reuse attacks.
///
/// **Use when:**
/// - Aggregating signatures from a single entity/keypair
/// - All signatures belong to the same XMSS tree
/// - Optimizing for minimal proof size (shared public key stored once)
///
/// **Validation rules:**
/// - Each epoch must be unique within the batch
/// - Items should have `public_key = None` (shared key stored in batch)
///
/// ## `MultiKey`
///
/// Signatures may come from different XMSS public keys. Each (public_key, epoch)
/// pair must be unique within the batch.
///
/// **Use when:**
/// - Aggregating signatures from multiple entities
/// - Combining signatures from different XMSS trees
/// - Flexible batch composition
///
/// **Validation rules:**
/// - Each (public_key, epoch) combination must be unique
/// - All items must have `public_key = Some(...)`
///
/// # Examples
///
/// ```
/// use sig_agg::AggregationMode;
///
/// # let single_signer = true;
/// // Choose mode based on your use case
/// let mode = if single_signer {
///     AggregationMode::SingleKey
/// } else {
///     AggregationMode::MultiKey
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AggregationMode {
    /// All signatures share the same public key (unique epochs required)
    SingleKey,
    /// Signatures may have different public keys (unique key-epoch pairs required)
    MultiKey,
}

/// Represents a single XMSS signature with its verification context.
///
/// A `VerificationItem` contains all the information needed to verify one XMSS
/// signature: the message, the epoch (one-time signature index), the signature
/// itself, and optionally the public key.
///
/// # Fields
///
/// * `message` - The message that was signed (fixed-length array)
/// * `epoch` - The XMSS epoch/index used for this signature (must be unique per key)
/// * `signature` - The XMSS signature data
/// * `public_key` - Optional public key:
///   - `None` for SingleKey mode (shared key stored in batch)
///   - `Some(pk)` for MultiKey mode (each item has its own key)
///
/// # Examples
///
/// ## Creating a VerificationItem for SingleKey Mode
///
/// ```no_run
/// use sig_agg::VerificationItem;
/// use hashsig::{MESSAGE_LENGTH, signature::SignatureScheme};
/// # use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1 as XMSSSignature;
///
/// # let sk = unimplemented!();
/// # let message = [0u8; MESSAGE_LENGTH];
/// # let epoch = 0u32;
/// let signature = XMSSSignature::sign(&sk, epoch, &message)
///     .expect("Signing failed");
///
/// let item = VerificationItem {
///     message,
///     epoch,
///     signature,
///     public_key: None,  // SingleKey mode
/// };
/// ```
///
/// ## Creating a VerificationItem for MultiKey Mode
///
/// ```no_run
/// use sig_agg::VerificationItem;
/// # use hashsig::{MESSAGE_LENGTH, signature::SignatureScheme};
/// # use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1 as XMSSSignature;
///
/// # let sk = unimplemented!();
/// # let pk = unimplemented!();
/// # let message = [0u8; MESSAGE_LENGTH];
/// # let epoch = 0u32;
/// let signature = XMSSSignature::sign(&sk, epoch, &message)
///     .expect("Signing failed");
///
/// let item = VerificationItem {
///     message,
///     epoch,
///     signature,
///     public_key: Some(pk),  // MultiKey mode requires public key
/// };
/// ```
///
/// # Serialization
///
/// `VerificationItem` implements `Serialize` and `Deserialize` for zkVM I/O
/// compatibility. Items are serialized when passed to the zkVM guest program.
#[derive(Serialize, Deserialize)]
pub struct VerificationItem {
    /// Message that was signed (fixed-length byte array)
    pub message: [u8; MESSAGE_LENGTH],
    /// Epoch (XMSS one-time signature index) when signature was created
    pub epoch: u32,
    /// XMSS signature data
    pub signature: <XMSSSignature as SignatureScheme>::Signature,
    /// Public key (None for SingleKey mode, Some for MultiKey mode)
    pub public_key: Option<<XMSSSignature as SignatureScheme>::PublicKey>,
}

/// Batch of signatures ready for zkVM verification.
///
/// An `AggregationBatch` represents a validated collection of XMSS signatures
/// that will be verified together in the zkVM to produce a succinct proof.
///
/// # Fields
///
/// * `mode` - Aggregation mode (SingleKey or MultiKey)
/// * `public_key` - Shared public key for SingleKey mode, `None` for MultiKey mode
/// * `items` - Vector of verification items to be verified
///
/// # Usage
///
/// Batches are created by the [`aggregate`](crate::aggregate) function after
/// validation. The batch is then serialized and passed to the zkVM guest program
/// for proof generation.
///
/// # Examples
///
/// ## Creating a SingleKey Batch
///
/// ```no_run
/// use sig_agg::{aggregate, AggregationMode, VerificationItem};
///
/// # let items: Vec<VerificationItem> = vec![];
/// # let shared_pk = unimplemented!();
/// let mut batch = aggregate(items, AggregationMode::SingleKey)
///     .expect("Aggregation failed");
///
/// // Set shared public key for SingleKey mode
/// batch.public_key = Some(shared_pk);
/// ```
///
/// ## Creating a MultiKey Batch
///
/// ```no_run
/// use sig_agg::{aggregate, AggregationMode, VerificationItem};
///
/// # let items: Vec<VerificationItem> = vec![];
/// let batch = aggregate(items, AggregationMode::MultiKey)
///     .expect("Aggregation failed");
///
/// // batch.public_key will be None (keys stored in each item)
/// assert!(batch.public_key.is_none());
/// ```
///
/// # Host vs Guest
///
/// - **Host side**: Batches are created and serialized for zkVM input
/// - **Guest side**: Batches are deserialized and verified within zkVM
#[derive(Serialize, Deserialize)]
pub struct AggregationBatch {
    /// Aggregation mode determining verification logic
    pub mode: AggregationMode,
    /// Shared public key (Some for SingleKey mode, None for MultiKey mode)
    pub public_key: Option<<XMSSSignature as SignatureScheme>::PublicKey>,
    /// Collection of verification items to verify
    pub items: Vec<VerificationItem>,
}

/// Metadata about zkVM proof generation.
///
/// Contains information about when and how a proof was generated, including
/// zkVM configuration parameters and batch size.
///
/// # Fields
///
/// * `timestamp` - Unix timestamp (seconds since epoch) when proof was generated
/// * `batch_size` - Number of signatures verified in this proof
/// * `memory_size` - zkVM memory size used during proof generation
/// * `trace_length` - Maximum trace length configured for zkVM
///
/// # Examples
///
/// ```
/// use sig_agg::ProofMetadata;
///
/// let metadata = ProofMetadata {
///     timestamp: 1234567890,
///     batch_size: 1000,
///     memory_size: 10240,   // 10MB
///     trace_length: 65536,  // Max trace entries
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Unix timestamp (seconds) when proof was generated
    pub timestamp: u64,
    /// Number of signatures verified in this proof
    pub batch_size: usize,
    /// zkVM memory size used (in MB)
    pub memory_size: usize,
    /// Maximum zkVM trace length configured
    pub trace_length: usize,
}

/// Succinct aggregation proof from zkVM verification.
///
/// An `AggregationProof` contains a zero-knowledge proof that N XMSS signatures
/// were successfully verified, along with metadata about the verification.
/// The proof size is constant regardless of batch size, providing space savings.
///
/// # Fields
///
/// * `proof` - Serialized Jolt zkVM proof bytes
/// * `verified_count` - Number of signatures successfully verified
/// * `mode` - Aggregation mode used (SingleKey or MultiKey)
/// * `metadata` - Proof generation metadata (timestamp, batch size, zkVM config)
///
/// # Proof Verification
///
/// The proof can be verified independently by anyone with:
/// 1. The proof bytes
/// 2. The original batch data (for commitment)
/// 3. The zkVM verifier preprocessing data
///
/// Verification is fast (typically < 5 seconds) and proves that all N signatures
/// in the batch were valid at the time of proof generation.
///
/// # Space Savings
///
/// For a batch of N signatures:
/// - Individual signatures: N * (signature_size + metadata_size)
/// - Aggregation proof: O(1) constant size (typically < 1MB)
///
/// Space savings increase linearly with batch size.
///
/// # Examples
///
/// ```no_run
/// use sig_agg::{AggregationProof, AggregationMode, ProofMetadata};
///
/// # let proof_bytes = vec![];
/// // After zkVM proof generation
/// let proof = AggregationProof {
///     proof: proof_bytes,
///     verified_count: 1000,
///     mode: AggregationMode::SingleKey,
///     metadata: ProofMetadata {
///         timestamp: 1234567890,
///         batch_size: 1000,
///         memory_size: 10240,
///         trace_length: 65536,
///     },
/// };
///
/// println!("Verified {} signatures", proof.verified_count);
/// println!("Proof size: {} bytes", proof.proof.len());
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationProof {
    /// Serialized Jolt zkVM proof bytes (constant size)
    pub proof: Vec<u8>,
    /// Number of signatures verified in this proof
    pub verified_count: u32,
    /// Aggregation mode used during verification
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
        let signature = XMSSSignature::sign(sk, epoch, &message).expect("Signing should succeed");

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
        let deserialized: VerificationItem =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

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
        let deserialized: AggregationBatch =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

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
        let deserialized: AggregationProof =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

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
