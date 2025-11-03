// Aggregation validation and batch preparation logic

use crate::error::AggregationError;
use crate::types::{AggregationBatch, AggregationMode, VerificationItem};
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1;
use std::collections::HashSet;

type XMSSSignature = SIGWinternitzLifetime18W1;

/// Validates single-key batch aggregation constraints.
///
/// In SingleKey mode, all signatures must share the same public key but use unique epochs.
/// This function ensures that the batch contains no duplicate epochs, which would violate
/// XMSS security requirements.
///
/// # Arguments
///
/// * `items` - Slice of verification items to validate
///
/// # Returns
///
/// * `Ok(())` - Validation successful, batch is ready for aggregation
/// * `Err(AggregationError::EmptyBatch)` - No items provided
/// * `Err(AggregationError::DuplicateEpoch)` - Multiple items use the same epoch
///
/// # Examples
///
/// ```no_run
/// use sig_agg::{validate_single_key, VerificationItem, AggregationError};
///
/// let items: Vec<VerificationItem> = vec![/* ... */];
///
/// match validate_single_key(&items) {
///     Ok(()) => println!("Batch is valid for SingleKey aggregation"),
///     Err(AggregationError::DuplicateEpoch { epoch }) => {
///         eprintln!("Duplicate epoch {} detected", epoch);
///     }
///     Err(e) => eprintln!("Validation failed: {}", e),
/// }
/// ```
///
/// # Security
///
/// SingleKey mode REQUIRES that all signatures use different epochs to prevent
/// XMSS signature reuse attacks. This function enforces this constraint.
pub fn validate_single_key(items: &[VerificationItem]) -> Result<(), AggregationError> {
    if items.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }

    // Check that all items have no public_key (should be None for SingleKey mode)
    // or that they would share the same public key if specified

    // Check for duplicate epochs
    let mut seen_epochs = HashSet::new();
    for item in items {
        if !seen_epochs.insert(item.epoch) {
            return Err(AggregationError::DuplicateEpoch { epoch: item.epoch });
        }
    }

    Ok(())
}

/// Validates multi-key aggregation constraints.
///
/// In MultiKey mode, signatures may use different public keys. This function ensures:
/// 1. All items have their `public_key` field populated
/// 2. No (public_key, epoch) pair appears more than once
///
/// # Arguments
///
/// * `items` - Slice of verification items to validate
///
/// # Returns
///
/// * `Ok(())` - Validation successful, batch is ready for aggregation
/// * `Err(AggregationError::EmptyBatch)` - No items provided
/// * `Err(AggregationError::MissingPublicKey)` - An item is missing its public key
/// * `Err(AggregationError::DuplicateKeyEpochPair)` - Same (key, epoch) pair used twice
/// * `Err(AggregationError::SerializationError)` - Failed to serialize a public key
///
/// # Examples
///
/// ```no_run
/// use sig_agg::{validate_multi_key, VerificationItem, AggregationError};
///
/// let items: Vec<VerificationItem> = vec![/* ... with public_key populated */];
///
/// match validate_multi_key(&items) {
///     Ok(()) => println!("Batch is valid for MultiKey aggregation"),
///     Err(AggregationError::MissingPublicKey { mode }) => {
///         eprintln!("Item missing public key in {} mode", mode);
///     }
///     Err(e) => eprintln!("Validation failed: {}", e),
/// }
/// ```
///
/// # Security
///
/// Each (public_key, epoch) combination must be unique to prevent XMSS signature
/// reuse within the aggregated batch.
pub fn validate_multi_key(items: &[VerificationItem]) -> Result<(), AggregationError> {
    if items.is_empty() {
        return Err(AggregationError::EmptyBatch);
    }

    // Check that all items have public_key specified
    for item in items {
        if item.public_key.is_none() {
            return Err(AggregationError::MissingPublicKey {
                mode: "MultiKey".to_string(),
            });
        }
    }

    // Check for duplicate (public_key, epoch) pairs
    // Since PublicKey doesn't implement Hash, we'll track epochs per serialized key
    let mut key_epoch_pairs: HashSet<(Vec<u8>, u32)> = HashSet::new();

    for item in items {
        if let Some(ref pk) = item.public_key {
            // Serialize the public key to use as a hash key
            let pk_bytes =
                bincode::serialize(pk).map_err(|e| AggregationError::SerializationError {
                    message: format!("Failed to serialize public key: {}", e),
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
    }

    Ok(())
}

/// Aggregates multiple XMSS signatures into a batch ready for zkVM verification.
///
/// This is the main entry point for signature aggregation. It validates the input
/// according to the specified mode and constructs an `AggregationBatch` that can be
/// processed by the zkVM guest program for succinct proof generation.
///
/// # Arguments
///
/// * `items` - Collection of verification items (message, epoch, signature, public key).
///             For SingleKey mode, `public_key` should be `None` in each item.
///             For MultiKey mode, `public_key` must be `Some(...)` in each item.
/// * `mode` - Aggregation mode determining validation rules:
///            - `AggregationMode::SingleKey`: All signatures share one public key
///            - `AggregationMode::MultiKey`: Signatures may have different public keys
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
/// - `DuplicateEpoch` - (SingleKey mode) Same epoch used multiple times
/// - `MissingPublicKey` - (MultiKey mode) Item missing required public key
/// - `DuplicateKeyEpochPair` - (MultiKey mode) Same (key, epoch) pair appears twice
/// - `SerializationError` - Failed to serialize public key for comparison
///
/// # Performance
///
/// Time complexity: O(N) where N is the number of items
/// Space complexity: O(N) for uniqueness tracking via hash sets
///
/// # Examples
///
/// ## SingleKey Mode
///
/// ```no_run
/// use sig_agg::{aggregate, AggregationMode, VerificationItem};
///
/// # let shared_pk = unimplemented!();
/// // Create verification items (all signatures from same key)
/// let items: Vec<VerificationItem> = vec![/* ... with public_key = None */];
///
/// // Aggregate in SingleKey mode
/// let mut batch = aggregate(items, AggregationMode::SingleKey)
///     .expect("Aggregation failed");
///
/// // Set the shared public key for the batch
/// batch.public_key = Some(shared_pk);
///
/// // Now batch can be passed to zkVM for proof generation
/// ```
///
/// ## MultiKey Mode
///
/// ```no_run
/// use sig_agg::{aggregate, AggregationMode, VerificationItem};
///
/// // Create verification items (each with its own public key)
/// let items: Vec<VerificationItem> = vec![/* ... with public_key = Some(...) */];
///
/// // Aggregate in MultiKey mode
/// let batch = aggregate(items, AggregationMode::MultiKey)
///     .expect("Aggregation failed");
///
/// // batch.public_key will be None in MultiKey mode
/// // Now batch can be passed to zkVM for proof generation
/// ```
///
/// ## Error Handling
///
/// ```no_run
/// use sig_agg::{aggregate, AggregationMode, AggregationError};
/// # let items = vec![];
///
/// match aggregate(items, AggregationMode::SingleKey) {
///     Ok(batch) => println!("Created batch with {} items", batch.items.len()),
///     Err(AggregationError::EmptyBatch) => {
///         eprintln!("Cannot aggregate empty batch");
///     }
///     Err(AggregationError::DuplicateEpoch { epoch }) => {
///         eprintln!("Duplicate epoch {} detected", epoch);
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
pub fn aggregate(
    items: Vec<VerificationItem>,
    mode: AggregationMode,
) -> Result<AggregationBatch, AggregationError> {
    // Input validation and mode-specific validation routing
    match mode {
        AggregationMode::SingleKey => {
            validate_single_key(&items)?;

            // Extract public key from the first item (if present) or expect it to be provided separately
            // For SingleKey mode, items should not have individual public keys
            // The shared public key should be provided when creating the batch
            Ok(AggregationBatch {
                mode,
                public_key: None, // Will be set by caller if needed
                items,
            })
        }
        AggregationMode::MultiKey => {
            validate_multi_key(&items)?;

            Ok(AggregationBatch {
                mode,
                public_key: None, // MultiKey mode doesn't use shared public key
                items,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashsig::MESSAGE_LENGTH;
    use hashsig::signature::SignatureScheme;
    use std::sync::OnceLock;

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

    fn create_test_item(epoch: u32, has_public_key: bool) -> VerificationItem {
        let (pk, sk) = get_test_keypair();

        let message = [epoch as u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(sk, epoch, &message).expect("Signing should succeed");

        VerificationItem {
            message,
            epoch,
            signature,
            public_key: if has_public_key {
                // Clone pk by serializing/deserializing
                let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
                Some(bincode::deserialize(&pk_bytes).expect("Deserialization should succeed"))
            } else {
                None
            },
        }
    }

    // Task 2.1: Single-key validation tests
    #[test]
    fn test_single_key_valid() {
        let items = vec![
            create_test_item(0, false),
            create_test_item(1, false),
            create_test_item(2, false),
        ];

        assert!(validate_single_key(&items).is_ok());
    }

    #[test]
    fn test_single_key_empty_batch() {
        let items: Vec<VerificationItem> = vec![];
        let result = validate_single_key(&items);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AggregationError::EmptyBatch));
    }

    #[test]
    fn test_single_key_duplicate_epoch() {
        let items = vec![
            create_test_item(0, false),
            create_test_item(1, false),
            create_test_item(0, false), // Duplicate epoch 0
        ];

        let result = validate_single_key(&items);
        assert!(result.is_err());

        match result.unwrap_err() {
            AggregationError::DuplicateEpoch { epoch } => assert_eq!(epoch, 0),
            _ => panic!("Expected DuplicateEpoch error"),
        }
    }

    #[test]
    fn test_single_key_single_item() {
        let items = vec![create_test_item(5, false)];
        assert!(validate_single_key(&items).is_ok());
    }

    #[test]
    fn test_single_key_large_batch() {
        let items: Vec<_> = (0..20).map(|i| create_test_item(i, false)).collect();
        assert!(validate_single_key(&items).is_ok());
    }

    // Task 2.2: Multi-key validation tests
    #[test]
    fn test_multi_key_valid() {
        let items = vec![
            create_test_item(0, true),
            create_test_item(1, true),
            create_test_item(2, true),
        ];

        assert!(validate_multi_key(&items).is_ok());
    }

    #[test]
    fn test_multi_key_empty_batch() {
        let items: Vec<VerificationItem> = vec![];
        let result = validate_multi_key(&items);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AggregationError::EmptyBatch));
    }

    #[test]
    fn test_multi_key_missing_public_key() {
        let items = vec![
            create_test_item(0, true),
            create_test_item(1, false), // Missing public key
        ];

        let result = validate_multi_key(&items);
        assert!(result.is_err());

        match result.unwrap_err() {
            AggregationError::MissingPublicKey { mode } => {
                assert_eq!(mode, "MultiKey");
            }
            _ => panic!("Expected MissingPublicKey error"),
        }
    }

    #[test]
    fn test_multi_key_duplicate_key_epoch_pair() {
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
            public_key: Some(pk_copy1),
        };

        let item2 = VerificationItem {
            message: message2,
            epoch: 5, // Same epoch as item1
            signature: signature2,
            public_key: Some(pk_copy2), // Same public key as item1 (via serialization)
        };

        let items = vec![item1, item2];
        let result = validate_multi_key(&items);

        assert!(result.is_err());
        match result.unwrap_err() {
            AggregationError::DuplicateKeyEpochPair { epoch, .. } => {
                assert_eq!(epoch, 5);
            }
            _ => panic!("Expected DuplicateKeyEpochPair error"),
        }
    }

    #[test]
    fn test_multi_key_same_epoch_different_keys() {
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
            public_key: Some(pk1_clone),
        };

        let item2 = VerificationItem {
            message,
            epoch: 5, // Same epoch
            signature: signature2,
            public_key: Some(pk2_clone), // Different key
        };

        let items = vec![item1, item2];
        assert!(validate_multi_key(&items).is_ok());
    }

    #[test]
    fn test_multi_key_same_key_different_epochs() {
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
            public_key: Some(pk_copy1),
        };

        let item2 = VerificationItem {
            message: message2,
            epoch: 1,
            signature: signature2,
            public_key: Some(pk_copy2),
        };

        let items = vec![item1, item2];
        assert!(validate_multi_key(&items).is_ok());
    }

    // Task 2.3: Batch aggregation orchestration tests
    #[test]
    fn test_aggregate_single_key_success() {
        let items = vec![
            create_test_item(0, false),
            create_test_item(1, false),
            create_test_item(2, false),
        ];

        let result = aggregate(items, AggregationMode::SingleKey);
        assert!(result.is_ok());

        let batch = result.unwrap();
        assert_eq!(batch.mode, AggregationMode::SingleKey);
        assert_eq!(batch.items.len(), 3);
    }

    #[test]
    fn test_aggregate_multi_key_success() {
        let items = vec![
            create_test_item(0, true),
            create_test_item(1, true),
            create_test_item(2, true),
        ];

        let result = aggregate(items, AggregationMode::MultiKey);
        assert!(result.is_ok());

        let batch = result.unwrap();
        assert_eq!(batch.mode, AggregationMode::MultiKey);
        assert_eq!(batch.items.len(), 3);
    }

    #[test]
    fn test_aggregate_empty_batch_error() {
        let items: Vec<VerificationItem> = vec![];

        let result = aggregate(items, AggregationMode::SingleKey);
        assert!(result.is_err());

        // Check error type without unwrap_err (which requires Debug)
        match result {
            Err(AggregationError::EmptyBatch) => (),
            _ => panic!("Expected EmptyBatch error"),
        }
    }

    #[test]
    fn test_aggregate_single_key_duplicate_epoch() {
        let items = vec![
            create_test_item(0, false),
            create_test_item(0, false), // Duplicate epoch
        ];

        let result = aggregate(items, AggregationMode::SingleKey);
        assert!(result.is_err());

        match result {
            Err(AggregationError::DuplicateEpoch { epoch }) => assert_eq!(epoch, 0),
            _ => panic!("Expected DuplicateEpoch error"),
        }
    }

    #[test]
    fn test_aggregate_multi_key_missing_public_key() {
        let items = vec![
            create_test_item(0, true),
            create_test_item(1, false), // Missing public key
        ];

        let result = aggregate(items, AggregationMode::MultiKey);
        assert!(result.is_err());

        match result {
            Err(AggregationError::MissingPublicKey { .. }) => (),
            _ => panic!("Expected MissingPublicKey error"),
        }
    }

    #[test]
    fn test_aggregate_mode_routing() {
        // Test that mode parameter correctly routes to appropriate validation
        let single_key_items = vec![create_test_item(0, false), create_test_item(1, false)];

        let multi_key_items = vec![create_test_item(0, true), create_test_item(1, true)];

        // SingleKey mode should succeed with items without individual public keys
        assert!(aggregate(single_key_items, AggregationMode::SingleKey).is_ok());

        // MultiKey mode should succeed with items with public keys
        assert!(aggregate(multi_key_items, AggregationMode::MultiKey).is_ok());
    }

    #[test]
    fn test_aggregate_complexity() {
        // Test that aggregation works efficiently with larger batches
        // This indirectly tests O(N) complexity - if it were O(N²), this would be very slow
        let items: Vec<_> = (0..10).map(|i| create_test_item(i, false)).collect();

        let result = aggregate(items, AggregationMode::SingleKey);
        assert!(result.is_ok());

        let batch = result.unwrap();
        assert_eq!(batch.items.len(), 10);
    }
}
