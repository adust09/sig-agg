//! zkVM integration tests for the Jolt benchmark
//!
//! These tests verify guest program compilation, proof generation,
//! and proof verification functionality.

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};

type XMSSSignature = SIGWinternitzLifetime18W1;

use guest::{AggregationBatch, AggregationMode, VerificationItem};

/// Test: Guest program compilation succeeds
#[test]
fn test_guest_compilation() {
    println!("Testing guest program compilation...");

    let target_dir = "/tmp/jolt-test-compilation";
    let _program = guest::compile_verify_aggregation(target_dir);

    assert!(
        std::path::Path::new(target_dir).exists(),
        "Compilation should create target directory"
    );

    println!("✓ Guest program compiled successfully");
}

/// Test: Proof generation for small batch (10 signatures)
#[test]
#[ignore] // Slow test (~10-15 seconds)
fn test_proof_generation() {
    println!("Testing proof generation (10 signatures)...");

    let mut rng = rand::rng();
    let (pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 15);

    let items: Vec<VerificationItem> = (0..10)
        .map(|i| {
            let mut local_rng = rand::rng();
            let epoch = i as u32;
            let message = [i as u8; MESSAGE_LENGTH];
            let signature = XMSSSignature::sign(&mut local_rng, &sk, epoch, &message)
                .expect("Signing failed");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: None,
            }
        })
        .collect();

    let batch = AggregationBatch {
        mode: AggregationMode::SingleKey,
        public_key: Some(pk),
        items,
    };

    let target_dir = "/tmp/jolt-test-proof-gen";
    let mut program = guest::compile_verify_aggregation(target_dir);
    let prover_preprocessing = guest::preprocess_prover_verify_aggregation(&mut program);
    let prove_fn = guest::build_prover_verify_aggregation(program, prover_preprocessing);

    let (verified_count, _proof, _io) = prove_fn(batch);

    assert_eq!(verified_count, 10);
    println!("✓ Generated proof for {} signatures", verified_count);
}

/// Test: End-to-end proof verification
#[test]
#[ignore] // Slow test (~15-20 seconds)
fn test_proof_verification() {
    println!("Testing proof verification...");

    let mut rng = rand::rng();
    let (pk, sk) = XMSSSignature::key_gen(&mut rng, 0, 15);

    // Clone pk via serialization for later use
    let pk_bytes = bincode::serialize(&pk).expect("PK serialization failed");
    let pk_clone = bincode::deserialize(&pk_bytes).expect("PK deserialization failed");

    // Helper to generate items
    let gen_items = || -> Vec<VerificationItem> {
        (0..10)
            .map(|i| {
                let mut local_rng = rand::rng();
                let epoch = i as u32;
                let message = [i as u8; MESSAGE_LENGTH];
                let signature = XMSSSignature::sign(&mut local_rng, &sk, epoch, &message)
                    .expect("Signing failed");

                VerificationItem {
                    message,
                    epoch,
                    signature,
                    public_key: None,
                }
            })
            .collect()
    };

    let batch = AggregationBatch {
        mode: AggregationMode::SingleKey,
        public_key: Some(pk),
        items: gen_items(),
    };

    let target_dir = "/tmp/jolt-test-verify";
    let mut program = guest::compile_verify_aggregation(target_dir);
    let prover_preprocessing = guest::preprocess_prover_verify_aggregation(&mut program);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_verify_aggregation(&prover_preprocessing);

    let prove_fn = guest::build_prover_verify_aggregation(program, prover_preprocessing);
    let verify_fn = guest::build_verifier_verify_aggregation(verifier_preprocessing);

    let (verified_count, proof, io) = prove_fn(batch);
    assert_eq!(verified_count, 10);

    let batch_verify = AggregationBatch {
        mode: AggregationMode::SingleKey,
        public_key: Some(pk_clone),
        items: gen_items(),
    };

    let is_valid = verify_fn(batch_verify, verified_count, io.panic, proof);
    assert!(is_valid);

    println!("✓ Proof verified successfully");
}
