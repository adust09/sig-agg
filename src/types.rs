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

/// Represents a single XMSS signature with its verification context.
///
/// A `VerificationItem` contains all the information needed to verify one XMSS
/// signature: the message, the epoch (one-time signature index), the signature,
/// and the public key.
///
/// # Fields
///
/// * `message` - The message that was signed (fixed-length array)
/// * `epoch` - The XMSS epoch/index used for this signature (must be unique per key)
/// * `signature` - The XMSS signature data
/// * `public_key` - The public key used to create this signature
///
/// # Validation Rules
///
/// Each (public_key, epoch) combination must be unique within a batch to prevent
/// XMSS signature reuse attacks.
///
/// # Examples
///
/// ```no_run
/// use sig_agg::VerificationItem;
/// use hashsig::{MESSAGE_LENGTH, signature::SignatureScheme};
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
///     public_key: pk,
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
    /// Public key used to create this signature
    pub public_key: <XMSSSignature as SignatureScheme>::PublicKey,
}

/// Batch of signatures ready for zkVM verification.
///
/// An `AggregationBatch` represents a validated collection of XMSS signatures
/// that will be verified together in the zkVM to produce a succinct proof.
///
/// # Fields
///
/// * `items` - Vector of verification items to be verified
///
/// # Usage
///
/// Batches are created by the [`aggregate`](crate::aggregate) function after
/// validation. The batch is then serialized and passed to the zkVM guest program
/// for proof generation.
///
/// # Validation Rules
///
/// Each (public_key, epoch) combination must be unique within the batch to prevent
/// XMSS signature reuse attacks.
///
/// # Examples
///
/// ```no_run
/// use sig_agg::{aggregate, VerificationItem};
///
/// # let items: Vec<VerificationItem> = vec![];
/// let batch = aggregate(items)
///     .expect("Aggregation failed");
/// ```
///
/// # Host vs Guest
///
/// - **Host side**: Batches are created and serialized for zkVM input
/// - **Guest side**: Batches are deserialized and verified within zkVM
#[derive(Serialize, Deserialize)]
pub struct AggregationBatch {
    /// Collection of verification items to verify
    pub items: Vec<VerificationItem>,
}

// Debug implementations for types containing non-Debug XMSS cryptographic primitives
impl std::fmt::Debug for VerificationItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationItem")
            .field("epoch", &self.epoch)
            .field(
                "message",
                &format_args!(
                    "[{:02x} {:02x} {:02x} {:02x}...] ({} bytes)",
                    self.message[0],
                    self.message[1],
                    self.message[2],
                    self.message[3],
                    self.message.len()
                ),
            )
            .field("signature", &"<XMSS Signature>")
            .field("public_key", &"<XMSS PublicKey>")
            .finish()
    }
}

impl std::fmt::Debug for AggregationBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AggregationBatch")
            .field("items", &format_args!("[{} items]", self.items.len()))
            .finish()
    }
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
/// use sig_agg::{AggregationProof, ProofMetadata};
///
/// # let proof_bytes = vec![];
/// // After zkVM proof generation
/// let proof = AggregationProof {
///     proof: proof_bytes,
///     verified_count: 1000,
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
            public_key: pk_clone,
        };

        // Test serialization
        let serialized = bincode::serialize(&item).expect("Serialization should succeed");

        // Test deserialization
        let deserialized: VerificationItem =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

        // Verify fields match
        assert_eq!(deserialized.message, item.message);
        assert_eq!(deserialized.epoch, item.epoch);
    }

    #[test]
    fn test_aggregation_batch_serde() {
        let (pk, sk) = get_test_keypair();

        // Clone pk for the items
        let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
        let pk_clone1 = bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");
        let pk_clone2 = bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        let item1 = VerificationItem {
            message: [1u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(sk, 0, &[1u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: pk_clone1,
        };

        let item2 = VerificationItem {
            message: [2u8; MESSAGE_LENGTH],
            epoch: 1,
            signature: XMSSSignature::sign(sk, 1, &[2u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: pk_clone2,
        };

        let batch = AggregationBatch {
            items: vec![item1, item2],
        };

        // Test serialization
        let serialized = bincode::serialize(&batch).expect("Serialization should succeed");

        // Test deserialization
        let deserialized: AggregationBatch =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

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
            metadata,
        };

        // Test serialization
        let serialized = bincode::serialize(&proof).expect("Serialization should succeed");

        // Test deserialization
        let deserialized: AggregationProof =
            bincode::deserialize(&serialized).expect("Deserialization should succeed");

        assert_eq!(deserialized.proof, proof.proof);
        assert_eq!(deserialized.verified_count, 100);
        assert_eq!(deserialized.metadata.batch_size, 100);
    }

    #[test]
    fn test_verification_item_creation() {
        let (pk, sk) = get_test_keypair();

        let pk_clone = bincode::deserialize(&bincode::serialize(pk).unwrap()).unwrap();

        let item = VerificationItem {
            message: [0u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(sk, 0, &[0u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: pk_clone,
        };

        // Verify item was created successfully
        assert_eq!(item.epoch, 0);
    }

    #[test]
    fn test_aggregation_batch_creation() {
        let (pk, sk) = get_test_keypair();

        let pk_clone = bincode::deserialize(&bincode::serialize(pk).unwrap()).unwrap();

        let item = VerificationItem {
            message: [0u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(sk, 0, &[0u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: pk_clone,
        };

        let batch = AggregationBatch { items: vec![item] };

        assert_eq!(batch.items.len(), 1);
    }

    #[test]
    fn test_verification_item_debug() {
        let (pk, sk) = get_test_keypair();

        let pk_clone = bincode::deserialize(&bincode::serialize(pk).unwrap()).unwrap();

        let item = VerificationItem {
            message: [0x42u8; MESSAGE_LENGTH],
            epoch: 5,
            signature: XMSSSignature::sign(sk, 5, &[0x42u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: pk_clone,
        };

        let debug_output = format!("{:?}", item);
        assert!(debug_output.contains("VerificationItem"));
        assert!(debug_output.contains("epoch: 5"));
        assert!(debug_output.contains("[42 42 42 42...]"));
        assert!(debug_output.contains("<XMSS PublicKey>"));
    }

    #[test]
    fn test_aggregation_batch_debug() {
        let (pk, sk) = get_test_keypair();

        let pk_bytes = bincode::serialize(pk).unwrap();
        let items: Vec<VerificationItem> = (0..3)
            .map(|i| VerificationItem {
                message: [i as u8; MESSAGE_LENGTH],
                epoch: i,
                signature: XMSSSignature::sign(sk, i, &[i as u8; MESSAGE_LENGTH])
                    .expect("Signing should succeed"),
                public_key: bincode::deserialize(&pk_bytes).unwrap(),
            })
            .collect();

        let batch = AggregationBatch { items };

        let debug_output = format!("{:?}", batch);
        assert!(debug_output.contains("AggregationBatch"));
        assert!(debug_output.contains("[3 items]"));
    }
}
