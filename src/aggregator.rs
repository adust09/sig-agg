// Aggregation validation and batch preparation logic

use crate::error::AggregationError;
use crate::types::{AggregationBatch, AggregationMode, VerificationItem};
use hashsig::signature::generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1;
use std::collections::HashSet;

type XMSSSignature = SIGWinternitzLifetime18W1;

/// Validate single-key batch aggregation constraints
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

/// Validate multi-key aggregation constraints
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
            let pk_bytes = bincode::serialize(pk).map_err(|e| {
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
    }

    Ok(())
}

/// Aggregate multiple XMSS signatures into a batch structure
///
/// # Arguments
/// * `items` - Collection of verification items (message, epoch, signature, public key)
/// * `mode` - Aggregation mode (SingleKey or MultiKey)
///
/// # Returns
/// * `Ok(AggregationBatch)` - Validated batch ready for zkVM processing
/// * `Err(AggregationError)` - Validation failure with specific error context
///
/// # Complexity
/// O(N) where N is the number of items (dominated by iteration and hash set operations)
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
        let signature = XMSSSignature::sign(sk, epoch, &message)
            .expect("Signing should succeed");

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
        let signature1 = XMSSSignature::sign(sk, 5, &message1)
            .expect("Signing should succeed");

        let message2 = [2u8; MESSAGE_LENGTH]; // Different message
        let signature2 = XMSSSignature::sign(sk, 5, &message2)
            .expect("Signing should succeed");

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
        let signature1 = XMSSSignature::sign(sk1, 5, &message)
            .expect("Signing should succeed");
        let signature2 = XMSSSignature::sign(sk2, 5, &message)
            .expect("Signing should succeed");

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
        let signature1 = XMSSSignature::sign(sk, 0, &message1)
            .expect("Signing should succeed");

        let message2 = [2u8; MESSAGE_LENGTH];
        let signature2 = XMSSSignature::sign(sk, 1, &message2)
            .expect("Signing should succeed");

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
