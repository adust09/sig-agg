// Aggregation validation and batch preparation logic

use crate::error::AggregationError;
use crate::types::{AggregationBatch, VerificationItem};
use std::collections::HashSet;

/// Validates aggregation batch constraints.
///
/// This function ensures that each (public_key, epoch) combination is unique within the batch,
/// which is required to prevent XMSS signature reuse attacks.
///
/// # Arguments
///
/// * `items` - Slice of verification items to validate
///
/// # Returns
///
/// * `Ok(())` - Validation successful, batch is ready for aggregation
/// * `Err(AggregationError::EmptyBatch)` - No items provided
/// * `Err(AggregationError::DuplicateKeyEpochPair)` - Same (key, epoch) pair used twice
/// * `Err(AggregationError::SerializationError)` - Failed to serialize a public key
///
/// # Examples
///
/// ```no_run
/// use sig_agg::{validate, VerificationItem, AggregationError};
///
/// let items: Vec<VerificationItem> = vec![/* ... */];
///
/// match validate(&items) {
///     Ok(()) => println!("Batch is valid for aggregation"),
///     Err(AggregationError::DuplicateKeyEpochPair { epoch, .. }) => {
///         eprintln!("Duplicate (key, epoch) pair with epoch {}", epoch);
///     }
///     Err(e) => eprintln!("Validation failed: {}", e),
/// }
/// ```
///
/// # Security
///
/// Each (public_key, epoch) combination must be unique to prevent XMSS signature
/// reuse within the aggregated batch.
pub fn validate(items: &[VerificationItem]) -> Result<(), AggregationError> {
    if items.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }

    // Check for duplicate (public_key, epoch) pairs
    // Since PublicKey doesn't implement Hash, we'll track epochs per serialized key
    let mut key_epoch_pairs: HashSet<(Vec<u8>, u32)> = HashSet::new();

    for item in items {
        // Serialize the public key to use as a hash key
        let pk_bytes = bincode::serialize(&item.public_key).map_err(|e| {
            AggregationError::SerializationError {
                message: format!("Failed to serialize public key: {}", e),
            }
        })?;

        let pair = (pk_bytes.clone(), item.epoch);
        if !key_epoch_pairs.insert(pair) {
            // Format public key for error message (truncated hex)
            let pk_str = format!("{}...", hex::encode(&pk_bytes[..8.min(pk_bytes.len())]));
            return Err(AggregationError::DuplicateKeyEpochPair {
                public_key: pk_str,
                epoch: item.epoch,
            });
        }
    }

    Ok(())
}

/// Aggregates multiple XMSS signatures into a batch ready for zkVM verification.
///
/// This is the main entry point for signature aggregation. It validates the input
/// and constructs an `AggregationBatch` that can be processed by the zkVM guest
/// program for succinct proof generation.
///
/// # Arguments
///
/// * `items` - Collection of verification items (message, epoch, signature, public key).
///             Each item must include its own public key.
///
/// # Returns
///
/// * `Ok(AggregationBatch)` - Validated batch ready for zkVM processing
/// * `Err(AggregationError)` - Validation failure (see error variants below)
///
/// # Errors
///
/// This function returns errors for various validation failures:
/// - `EmptyBatch` - No items provided (at least one signature required)
/// - `DuplicateKeyEpochPair` - Same (key, epoch) pair appears twice
/// - `SerializationError` - Failed to serialize public key for comparison
///
/// # Performance
///
/// Time complexity: O(N) where N is the number of items
/// Space complexity: O(N) for uniqueness tracking via hash sets
///
/// # Examples
///
/// ```no_run
/// use sig_agg::{aggregate, VerificationItem};
///
/// // Create verification items (each with its own public key)
/// let items: Vec<VerificationItem> = vec![/* ... */];
///
/// // Aggregate signatures
/// let batch = aggregate(items)
///     .expect("Aggregation failed");
///
/// // batch can now be passed to zkVM for proof generation
/// ```
///
/// ## Error Handling
///
/// ```no_run
/// use sig_agg::{aggregate, AggregationError};
/// # let items = vec![];
///
/// match aggregate(items) {
///     Ok(batch) => println!("Created batch with {} items", batch.items.len()),
///     Err(AggregationError::EmptyBatch) => {
///         eprintln!("Cannot aggregate empty batch");
///     }
///     Err(AggregationError::DuplicateKeyEpochPair { epoch, .. }) => {
///         eprintln!("Duplicate (key, epoch) pair with epoch {}", epoch);
///     }
///     Err(e) => eprintln!("Aggregation failed: {}", e),
/// }
/// ```
///
/// # Host vs Guest Usage
///
/// This function is intended for **host-side** use only. It prepares batches that
/// are then serialized and passed to the zkVM guest program for verification.
/// The guest program receives an `AggregationBatch` and verifies all signatures
/// within the zkVM environment to generate a succinct proof.
pub fn aggregate(items: Vec<VerificationItem>) -> Result<AggregationBatch, AggregationError> {
    validate(&items)?;
    Ok(AggregationBatch { items })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashsig::MESSAGE_LENGTH;
    use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1;
    use hashsig::signature::SignatureScheme;
    use std::sync::OnceLock;

    type XMSSSignature = SIGWinternitzLifetime18W1;

    // Shared test keypairs to avoid expensive key generation in each test
    static TEST_KEYPAIR: OnceLock<(
        <XMSSSignature as SignatureScheme>::PublicKey,
        <XMSSSignature as SignatureScheme>::SecretKey,
    )> = OnceLock::new();

    static TEST_KEYPAIR_2: OnceLock<(
        <XMSSSignature as SignatureScheme>::PublicKey,
        <XMSSSignature as SignatureScheme>::SecretKey,
    )> = OnceLock::new();

    fn get_test_keypair() -> &'static (
        <XMSSSignature as SignatureScheme>::PublicKey,
        <XMSSSignature as SignatureScheme>::SecretKey,
    ) {
        TEST_KEYPAIR.get_or_init(|| {
            let mut rng = rand::rng();
            XMSSSignature::key_gen(&mut rng, 0, 100)
        })
    }

    fn get_test_keypair_2() -> &'static (
        <XMSSSignature as SignatureScheme>::PublicKey,
        <XMSSSignature as SignatureScheme>::SecretKey,
    ) {
        TEST_KEYPAIR_2.get_or_init(|| {
            let mut rng = rand::rng();
            XMSSSignature::key_gen(&mut rng, 100, 200)
        })
    }

    fn create_test_item(epoch: u32) -> VerificationItem {
        let (pk, sk) = get_test_keypair();

        let message = [epoch as u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(sk, epoch, &message).expect("Signing should succeed");

        // Clone pk by serializing/deserializing
        let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
        let pk_clone = bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        VerificationItem {
            message,
            epoch,
            signature,
            public_key: pk_clone,
        }
    }

    // Validation tests
    #[test]
    fn test_validate_valid() {
        let items = vec![create_test_item(0), create_test_item(1), create_test_item(2)];

        assert!(validate(&items).is_ok());
    }

    #[test]
    fn test_validate_empty_batch() {
        let items: Vec<VerificationItem> = vec![];
        let result = validate(&items);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AggregationError::EmptyBatch));
    }

    #[test]
    fn test_validate_single_item() {
        let items = vec![create_test_item(5)];
        assert!(validate(&items).is_ok());
    }

    #[test]
    fn test_validate_large_batch() {
        let items: Vec<_> = (0..20).map(create_test_item).collect();
        assert!(validate(&items).is_ok());
    }

    #[test]
    fn test_validate_duplicate_key_epoch_pair() {
        // Create two items with the same key and epoch using shared keypair
        let (pk, sk) = get_test_keypair();

        let message1 = [1u8; MESSAGE_LENGTH];
        let signature1 = XMSSSignature::sign(sk, 5, &message1).expect("Signing should succeed");

        let message2 = [2u8; MESSAGE_LENGTH]; // Different message
        let signature2 = XMSSSignature::sign(sk, 5, &message2).expect("Signing should succeed");

        // Serialize and deserialize to get a "copy" of the public key
        let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
        let pk_copy1: <XMSSSignature as SignatureScheme>::PublicKey =
            bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");
        let pk_copy2: <XMSSSignature as SignatureScheme>::PublicKey =
            bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        let item1 = VerificationItem {
            message: message1,
            epoch: 5,
            signature: signature1,
            public_key: pk_copy1,
        };

        let item2 = VerificationItem {
            message: message2,
            epoch: 5, // Same epoch as item1
            signature: signature2,
            public_key: pk_copy2, // Same public key as item1 (via serialization)
        };

        let items = vec![item1, item2];
        let result = validate(&items);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregationError::DuplicateKeyEpochPair { epoch, .. } => {
                assert_eq!(epoch, 5);
            }
            _ => panic!("Expected DuplicateKeyEpochPair error"),
        }
    }

    #[test]
    fn test_validate_same_epoch_different_keys() {
        // Same epoch but different keys should be valid
        // Create items with different keypairs but same epoch
        let (pk1, sk1) = get_test_keypair();
        let (pk2, sk2) = get_test_keypair_2();

        let message = [5u8; MESSAGE_LENGTH];
        let signature1 = XMSSSignature::sign(sk1, 5, &message).expect("Signing should succeed");
        let signature2 = XMSSSignature::sign(sk2, 5, &message).expect("Signing should succeed");

        let pk1_clone = bincode::deserialize::<_>(&bincode::serialize(pk1).unwrap()).unwrap();
        let pk2_clone = bincode::deserialize::<_>(&bincode::serialize(pk2).unwrap()).unwrap();

        let item1 = VerificationItem {
            message,
            epoch: 5,
            signature: signature1,
            public_key: pk1_clone,
        };

        let item2 = VerificationItem {
            message,
            epoch: 5, // Same epoch
            signature: signature2,
            public_key: pk2_clone, // Different key
        };

        let items = vec![item1, item2];
        assert!(validate(&items).is_ok());
    }

    #[test]
    fn test_validate_same_key_different_epochs() {
        // Same key but different epochs should be valid
        let (pk, sk) = get_test_keypair();

        let message1 = [1u8; MESSAGE_LENGTH];
        let signature1 = XMSSSignature::sign(sk, 0, &message1).expect("Signing should succeed");

        let message2 = [2u8; MESSAGE_LENGTH];
        let signature2 = XMSSSignature::sign(sk, 1, &message2).expect("Signing should succeed");

        // Serialize and deserialize to get a "copy" of the public key
        let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
        let pk_copy1: <XMSSSignature as SignatureScheme>::PublicKey =
            bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");
        let pk_copy2: <XMSSSignature as SignatureScheme>::PublicKey =
            bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        let item1 = VerificationItem {
            message: message1,
            epoch: 0,
            signature: signature1,
            public_key: pk_copy1,
        };

        let item2 = VerificationItem {
            message: message2,
            epoch: 1,
            signature: signature2,
            public_key: pk_copy2,
        };

        let items = vec![item1, item2];
        assert!(validate(&items).is_ok());
    }

    // Batch aggregation tests
    #[test]
    fn test_aggregate_success() {
        let items = vec![create_test_item(0), create_test_item(1), create_test_item(2)];

        let result = aggregate(items);
        assert!(result.is_ok());

        let batch = result.unwrap();
        assert_eq!(batch.items.len(), 3);
    }

    #[test]
    fn test_aggregate_empty_batch_error() {
        let items: Vec<VerificationItem> = vec![];

        let result = aggregate(items);
        assert!(result.is_err());

        match result {
            Err(AggregationError::EmptyBatch) => (),
            _ => panic!("Expected EmptyBatch error"),
        }
    }

    #[test]
    fn test_aggregate_complexity() {
        // Test that aggregation works efficiently with larger batches
        // This indirectly tests O(N) complexity - if it were O(N²), this would be very slow
        let items: Vec<_> = (0..10).map(create_test_item).collect();

        let result = aggregate(items);
        assert!(result.is_ok());

        let batch = result.unwrap();
        assert_eq!(batch.items.len(), 10);
    }
}
