//! Error handling example
//!
//! This example demonstrates various error scenarios that can occur
//! during signature aggregation and how to handle them properly.
//!
//! Run with: `cargo run --example error_handling`

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use sig_agg::{AggregationError, AggregationMode, VerificationItem, aggregate};

type XMSSSignature = SIGWinternitzLifetime18W1;

fn main() {
    println!("=== Error Handling Example ===\n");

    // Scenario 1: Empty batch
    println!("1. Testing empty batch error...");
    test_empty_batch();
    println!();

    // Scenario 2: Duplicate epoch in SingleKey mode
    println!("2. Testing duplicate epoch error (SingleKey mode)...");
    test_duplicate_epoch();
    println!();

    // Scenario 3: Missing public key in MultiKey mode
    println!("3. Testing missing public key error (MultiKey mode)...");
    test_missing_public_key();
    println!();

    // Scenario 4: Duplicate (key, epoch) pair in MultiKey mode
    println!("4. Testing duplicate key-epoch pair error (MultiKey mode)...");
    test_duplicate_key_epoch_pair();
    println!();

    // Scenario 5: Successful aggregation with error recovery
    println!("5. Demonstrating error recovery pattern...");
    test_error_recovery();
    println!();

    println!("=== All Error Scenarios Tested ===");
}

/// Test 1: Empty batch error
fn test_empty_batch() {
    let items: Vec<VerificationItem> = vec![];

    match aggregate(items, AggregationMode::SingleKey) {
        Ok(_) => println!("   ✗ Expected error but got success"),
        Err(AggregationError::EmptyBatch) => {
            println!("   ✓ Correctly rejected empty batch");
            println!("     Error: At least one signature required");
        }
        Err(e) => println!("   ✗ Unexpected error: {}", e),
    }
}

/// Test 2: Duplicate epoch error
fn test_duplicate_epoch() {
    let mut rng = rand::rng();
    let (_, sk) = XMSSSignature::key_gen(&mut rng, 0, 10);

    let mut items = vec![];

    // Create two items with the same epoch
    for _ in 0..2 {
        let message = [1u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(&sk, 0, &message) // Same epoch: 0
            .expect("Signing should succeed");

        items.push(VerificationItem {
            message,
            epoch: 0, // Duplicate!
            signature,
            public_key: None,
        });
    }

    match aggregate(items, AggregationMode::SingleKey) {
        Ok(_) => println!("   ✗ Expected error but got success"),
        Err(AggregationError::DuplicateEpoch { epoch }) => {
            println!("   ✓ Correctly detected duplicate epoch");
            println!("     Error: Epoch {} used multiple times", epoch);
        }
        Err(e) => println!("   ✗ Unexpected error: {}", e),
    }
}

/// Test 3: Missing public key error
fn test_missing_public_key() {
    let mut rng = rand::rng();
    let (_, sk) = XMSSSignature::key_gen(&mut rng, 0, 10);

    let message = [1u8; MESSAGE_LENGTH];
    let signature = XMSSSignature::sign(&sk, 0, &message).expect("Signing should succeed");

    let items = vec![VerificationItem {
        message,
        epoch: 0,
        signature,
        public_key: None, // Missing public key in MultiKey mode!
    }];

    match aggregate(items, AggregationMode::MultiKey) {
        Ok(_) => println!("   ✗ Expected error but got success"),
        Err(AggregationError::MissingPublicKey { mode }) => {
            println!("   ✓ Correctly detected missing public key");
            println!("     Error: Public key required in {} mode", mode);
        }
        Err(e) => println!("   ✗ Unexpected error: {}", e),
    }
}

/// Test 4: Duplicate (key, epoch) pair error
fn test_duplicate_key_epoch_pair() {
    let mut rng = rand::rng();
    let (pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 10);

    let mut items = vec![];

    // Create two items with the same (key, epoch) pair
    for _ in 0..2 {
        let message = [1u8; MESSAGE_LENGTH];
        let signature = XMSSSignature::sign(&sk, 0, &message) // Same epoch
            .expect("Signing should succeed");

        // Clone public key
        let pk_bytes = bincode::serialize(&pk).unwrap();
        let pk_clone = bincode::deserialize(&pk_bytes).unwrap();

        items.push(VerificationItem {
            message,
            epoch: 0, // Same epoch with same key
            signature,
            public_key: Some(pk_clone),
        });
    }

    match aggregate(items, AggregationMode::MultiKey) {
        Ok(_) => println!("   ✗ Expected error but got success"),
        Err(AggregationError::DuplicateKeyEpochPair { epoch, .. }) => {
            println!("   ✓ Correctly detected duplicate (key, epoch) pair");
            println!("     Error: Epoch {} reused with same public key", epoch);
        }
        Err(e) => println!("   ✗ Unexpected error: {}", e),
    }
}

/// Test 5: Error recovery pattern
fn test_error_recovery() {
    let mut rng = rand::rng();
    let (pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 10);

    println!("   Attempting to create batch with duplicate epochs...");

    // First attempt with duplicates
    let bad_items = vec![
        create_item(&sk, 0),
        create_item(&sk, 0), // Duplicate!
    ];

    let result = aggregate(bad_items, AggregationMode::SingleKey);

    if let Err(AggregationError::DuplicateEpoch { epoch }) = result {
        println!("   ✓ Detected error: Duplicate epoch {}", epoch);
        println!("   ✓ Recovering: Creating batch with unique epochs...");

        // Retry with corrected data
        let good_items = vec![
            create_item(&sk, 0),
            create_item(&sk, 1), // Fixed: unique epoch
            create_item(&sk, 2),
        ];

        match aggregate(good_items, AggregationMode::SingleKey) {
            Ok(mut batch) => {
                batch.public_key = Some(pk);
                println!(
                    "   ✓ Successfully created batch with {} items",
                    batch.items.len()
                );
                println!("   ✓ Error recovery complete!");
            }
            Err(e) => println!("   ✗ Retry failed: {}", e),
        }
    } else {
        println!("   ✗ Expected DuplicateEpoch error");
    }
}

/// Helper function to create a verification item
fn create_item(sk: &<XMSSSignature as SignatureScheme>::SecretKey, epoch: u32) -> VerificationItem {
    let message = [epoch as u8; MESSAGE_LENGTH];
    let signature = XMSSSignature::sign(sk, epoch, &message).expect("Signing should succeed");

    VerificationItem {
        message,
        epoch,
        signature,
        public_key: None,
    }
}
