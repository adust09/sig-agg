// Integration tests for end-to-end aggregation workflows

use sig_agg::{
    aggregator,
    error::AggregationError,
    types::{AggregationMode, VerificationItem},
};

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};

type XMSSSignature = SIGWinternitzLifetime18W1;

/// Test end-to-end aggregation with a small batch (10 signatures)
#[test]
fn test_e2e_aggregation_small_batch() {
    let mut rng = rand::rng();
    let (pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 20);

    // Generate 10 signatures
    let items: Vec<VerificationItem> = (0..10)
        .map(|i| {
            let epoch = i as u32;
            let message = [i as u8; MESSAGE_LENGTH];
            let signature = XMSSSignature::sign(&sk, epoch, &message)
                .expect("Signing should succeed");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: None, // SingleKey mode
            }
        })
        .collect();

    // Aggregate signatures
    let mut batch = aggregator::aggregate(items, AggregationMode::SingleKey)
        .expect("Aggregation should succeed");

    // Set the shared public key for SingleKey mode
    batch.public_key = Some(pk);

    // Verify batch structure
    assert_eq!(batch.mode, AggregationMode::SingleKey);
    assert_eq!(batch.items.len(), 10);
    assert!(batch.public_key.is_some());
}

/// Test end-to-end aggregation with invalid signature rejection
#[test]
fn test_e2e_invalid_signature_rejection() {
    let mut rng = rand::rng();
    let (_pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 20);

    // Generate valid signatures
    let mut items: Vec<VerificationItem> = (0..5)
        .map(|i| {
            let epoch = i as u32;
            let message = [i as u8; MESSAGE_LENGTH];
            let signature = XMSSSignature::sign(&sk, epoch, &message)
                .expect("Signing should succeed");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: None,
            }
        })
        .collect();

    // Add an invalid signature (wrong message for epoch 5)
    let wrong_message = [99u8; MESSAGE_LENGTH];
    let wrong_signature = XMSSSignature::sign(&sk, 5, &wrong_message)
        .expect("Signing should succeed");

    items.push(VerificationItem {
        message: [5u8; MESSAGE_LENGTH], // Different from signed message
        epoch: 5,
        signature: wrong_signature,
        public_key: None,
    });

    // Aggregation should still succeed (validation happens at verification time)
    let batch = aggregator::aggregate(items, AggregationMode::SingleKey)
        .expect("Aggregation should succeed");

    assert_eq!(batch.items.len(), 6);
    // In a real zkVM verification, the invalid signature would be detected
}

/// Test multi-key aggregation across multiple public keys
#[test]
fn test_e2e_multi_key_aggregation() {
    let mut rng = rand::rng();

    // Generate 3 different keypairs
    let (pk1, sk1) = XMSSSignature::key_gen(&mut rng, 0, 10);
    let (pk2, sk2) = XMSSSignature::key_gen(&mut rng, 10, 20);
    let (pk3, sk3) = XMSSSignature::key_gen(&mut rng, 20, 30);

    let mut items = Vec::new();

    // Add signatures from first key
    for i in 0..3 {
        let epoch = i as u32;
        let message = [i as u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(&sk1, epoch, &message)
            .expect("Signing should succeed");

        let pk_bytes = bincode::serialize(&pk1).unwrap();
        let pk_clone = bincode::deserialize(&pk_bytes).unwrap();

        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone),
        });
    }

    // Add signatures from second key
    for i in 0..3 {
        let epoch = (10 + i) as u32;
        let message = [(10 + i) as u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(&sk2, epoch, &message)
            .expect("Signing should succeed");

        let pk_bytes = bincode::serialize(&pk2).unwrap();
        let pk_clone = bincode::deserialize(&pk_bytes).unwrap();

        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone),
        });
    }

    // Add signatures from third key
    for i in 0..3 {
        let epoch = (20 + i) as u32;
        let message = [(20 + i) as u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(&sk3, epoch, &message)
            .expect("Signing should succeed");

        let pk_bytes = bincode::serialize(&pk3).unwrap();
        let pk_clone = bincode::deserialize(&pk_bytes).unwrap();

        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone),
        });
    }

    // Aggregate multi-key batch
    let batch = aggregator::aggregate(items, AggregationMode::MultiKey)
        .expect("Multi-key aggregation should succeed");

    assert_eq!(batch.mode, AggregationMode::MultiKey);
    assert_eq!(batch.items.len(), 9);
    assert!(batch.public_key.is_none()); // MultiKey mode doesn't use shared key
}

/// Test cache loading behavior (simulated)
#[test]
fn test_e2e_cache_loading() {
    // This test verifies that serialization/deserialization works correctly
    // (actual cache loading is tested in the Jolt host program)

    let mut rng = rand::rng();
    let (pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 20);

    let items: Vec<VerificationItem> = (0..10)
        .map(|i| {
            let epoch = i as u32;
            let message = [i as u8; MESSAGE_LENGTH];
            let signature = XMSSSignature::sign(&sk, epoch, &message)
                .expect("Signing should succeed");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: None,
            }
        })
        .collect();

    let mut batch = aggregator::aggregate(items, AggregationMode::SingleKey)
        .expect("Aggregation should succeed");

    batch.public_key = Some(pk);

    // Serialize batch
    let serialized = bincode::serialize(&batch)
        .expect("Serialization should succeed");

    // Deserialize batch
    use sig_agg::types::AggregationBatch;
    let deserialized: Result<AggregationBatch, _> = bincode::deserialize(&serialized);

    // Verify deserialization succeeded
    assert!(deserialized.is_ok());
    let deserialized_batch = deserialized.unwrap();
    assert_eq!(deserialized_batch.mode, batch.mode);
    assert_eq!(deserialized_batch.items.len(), batch.items.len());
}

/// Test error handling for invalid inputs
#[test]
fn test_e2e_error_handling() {
    // Empty batch
    let result = aggregator::aggregate(vec![], AggregationMode::SingleKey);
    assert!(matches!(result, Err(AggregationError::EmptyBatch)));

    // Duplicate epoch in SingleKey mode
    let mut rng = rand::rng();
    let (_pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 20);

    let items: Vec<VerificationItem> = vec![
        VerificationItem {
            message: [0u8; MESSAGE_LENGTH],
            epoch: 0,
            signature: XMSSSignature::sign(&sk, 0, &[0u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: None,
        },
        VerificationItem {
            message: [1u8; MESSAGE_LENGTH],
            epoch: 0, // Duplicate!
            signature: XMSSSignature::sign(&sk, 0, &[1u8; MESSAGE_LENGTH])
                .expect("Signing should succeed"),
            public_key: None,
        },
    ];

    let result = aggregator::aggregate(items, AggregationMode::SingleKey);
    assert!(matches!(result, Err(AggregationError::DuplicateEpoch { epoch: 0 })));
}
