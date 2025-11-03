use std::{fs, path::Path, time::Instant};

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use rayon::{iter::IntoParallelIterator, prelude::*};

const NUM_SIGNATURES: usize = 1000;

// Use the guest types directly to avoid duplication
use guest::{AggregationBatch, AggregationMode, VerificationItem};

/// Generates or loads cached public key and 1000 signatures to be verified.
fn setup_benchmark_data() -> AggregationBatch {
    let cache_dir = "./tmp";
    let cache_file = "./tmp/benchmark_data.bin";

    // Try to load from cache first
    if Path::new(cache_file).exists() {
        println!("Loading benchmark data from cache...");
        let start = Instant::now();

        match fs::read(cache_file) {
            Ok(cached_data) => match bincode::deserialize::<AggregationBatch>(&cached_data) {
                Ok(data) => {
                    println!("Benchmark data loaded from cache in {:?}", start.elapsed());
                    return data;
                }
                Err(e) => {
                    println!("Failed to deserialize cached data: {}, regenerating...", e);
                }
            },
            Err(e) => {
                println!("Failed to read cache file: {}, regenerating...", e);
            }
        }
    }

    println!(
        "Generating fresh benchmark data: {} signatures...",
        NUM_SIGNATURES
    );
    let start = Instant::now();
    let mut rng = rand::rng();

    // Generate a key active only for the epochs we need, making this step fast.
    let (pk, sk) = SIGWinternitzLifetime18W1::key_gen(&mut rng, 0, NUM_SIGNATURES);

    // Generate 1000 signatures in parallel for speed.
    // For SingleKey mode, items don't include individual public keys
    let items: Vec<VerificationItem> = (0..NUM_SIGNATURES)
        .into_par_iter()
        .map(|i| {
            let mut thread_rng = rand::rng();
            let epoch = i as u32;
            let message: [u8; MESSAGE_LENGTH] = (0..MESSAGE_LENGTH)
                .map(|b| (i + b) as u8)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();

            let signature = SIGWinternitzLifetime18W1::sign(&mut thread_rng, &sk, epoch, &message)
                .expect("Signing failed");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: None, // SingleKey mode: shared public key in batch
            }
        })
        .collect();

    let aggregation_batch = AggregationBatch {
        mode: AggregationMode::SingleKey,
        public_key: Some(pk), // Shared public key for all signatures
        items,
    };

    // Cache the generated data
    if let Err(e) = fs::create_dir_all(cache_dir) {
        println!("Failed to create cache directory: {}", e);
    } else {
        match bincode::serialize(&aggregation_batch) {
            Ok(serialized_data) => {
                if let Err(e) = fs::write(cache_file, &serialized_data) {
                    println!("Failed to write cache file: {}", e);
                } else {
                    println!("Benchmark data cached for future runs");
                }
            }
            Err(e) => {
                println!("Failed to serialize data for caching: {}", e);
            }
        }
    }

    println!("Benchmark data generated in {:?}", start.elapsed());
    aggregation_batch
}

pub fn main() {
    println!("XMSS Signature Aggregation Benchmark - Jolt zkVM");
    println!("===================================================");
    println!("Mode: SingleKey aggregation ({} signatures)", NUM_SIGNATURES);
    println!();

    // 1. Setup Phase: Generate keys and signatures.
    let verification_data = setup_benchmark_data();

    // 2. Jolt Compilation and Preprocessing
    println!("Compiling and preprocessing guest program...");
    let start_preprocess = Instant::now();
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_aggregation(target_dir);

    let prover_preprocessing = guest::preprocess_prover_verify_aggregation(&mut program);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_verify_aggregation(&prover_preprocessing);
    println!("Jolt preprocessed in {:?}", start_preprocess.elapsed());

    let prove_verify_aggregation =
        guest::build_prover_verify_aggregation(program, prover_preprocessing);
    let verify_verify_aggregation = guest::build_verifier_verify_aggregation(verifier_preprocessing);

    // 3. Proving Phase
    println!(
        "Starting zkVM proof generation for {} aggregated signatures...",
        NUM_SIGNATURES
    );
    let start_prove = Instant::now();
    let (verified_count, proof, program_io) = prove_verify_aggregation(verification_data);
    let prove_time = start_prove.elapsed();
    println!("zkVM proof generated in {:?}", prove_time);
    println!(
        "Guest program verified {} signatures in aggregate",
        verified_count
    );

    // 4. Verification Phase
    println!("Verifying zkVM aggregation proof...");
    let start_verify = Instant::now();
    let verification_data_for_verify = setup_benchmark_data();
    let is_valid = verify_verify_aggregation(
        verification_data_for_verify,
        verified_count,
        program_io.panic,
        proof,
    );
    let verify_time = start_verify.elapsed();
    println!(
        "Aggregation proof is valid: {}! Verified in {:?}",
        is_valid, verify_time
    );

    // 5. Print Results
    println!("\nBENCHMARK RESULTS");
    println!("====================");
    println!("- Proving Time:       {:?}", prove_time);
    println!("- Verification Time:  {:?}", verify_time);
    println!(
        "\nProving Performance: {:.2} signatures/second",
        NUM_SIGNATURES as f64 / prove_time.as_secs_f64()
    );
}
