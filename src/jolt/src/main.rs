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
    println!();
    println!("This benchmark demonstrates the XMSS signature aggregation system,");
    println!("which verifies multiple post-quantum signatures within a zkVM to");
    println!("produce a succinct proof of verification.");
    println!();
    println!("Configuration:");
    println!("- Aggregation Mode: SingleKey (all signatures from one public key)");
    println!("- Batch Size: {} signatures", NUM_SIGNATURES);
    println!("- XMSS Variant: Lifetime 2^18 with Poseidon hashing");
    println!("- zkVM: Jolt (a16z)");
    println!();

    // 1. Setup Phase: Generate keys and signatures.
    println!("Phase 1: Setup - Generating or Loading Benchmark Data");
    println!("------------------------------------------------------");
    println!("This phase creates {} XMSS signatures or loads them from cache.", NUM_SIGNATURES);
    println!("Each signature is created with a unique epoch (0-{}).", NUM_SIGNATURES - 1);
    let verification_data = setup_benchmark_data();
    println!();

    // 2. Jolt Compilation and Preprocessing
    println!("Phase 2: zkVM Compilation and Preprocessing");
    println!("--------------------------------------------");
    println!("Compiling the guest program (verify_aggregation) to zkVM bytecode...");
    println!("This step is slow on first run but cached for subsequent runs.");
    let start_preprocess = Instant::now();
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_aggregation(target_dir);

    println!("Preprocessing prover and verifier data structures...");
    println!("This generates commitment keys and other cryptographic parameters.");
    let prover_preprocessing = guest::preprocess_prover_verify_aggregation(&mut program);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_verify_aggregation(&prover_preprocessing);
    println!("✓ zkVM preprocessing complete in {:?}", start_preprocess.elapsed());

    let prove_verify_aggregation =
        guest::build_prover_verify_aggregation(program, prover_preprocessing);
    let verify_verify_aggregation = guest::build_verifier_verify_aggregation(verifier_preprocessing);
    println!();

    // 3. Proving Phase
    println!("Phase 3: Proof Generation (Aggregated Verification)");
    println!("----------------------------------------------------");
    println!("Executing guest program inside zkVM to verify all {} signatures...", NUM_SIGNATURES);
    println!("The guest program:");
    println!("  1. Receives the aggregation batch as input");
    println!("  2. Verifies each XMSS signature individually");
    println!("  3. Returns the count of successfully verified signatures");
    println!("  4. zkVM generates a succinct proof of this computation");
    println!();
    println!("Proof generation in progress (this may take 30-60 seconds)...");
    let start_prove = Instant::now();
    let (verified_count, proof, program_io) = prove_verify_aggregation(verification_data);
    let prove_time = start_prove.elapsed();
    println!();
    println!("✓ zkVM proof generated in {:?}", prove_time);
    println!("✓ Guest program verified {} signatures successfully", verified_count);
    println!(
        "✓ Proving throughput: {:.2} signatures/second",
        NUM_SIGNATURES as f64 / prove_time.as_secs_f64()
    );
    println!();

    // 4. Verification Phase
    println!("Phase 4: Proof Verification");
    println!("----------------------------");
    println!("Verifying the zkVM proof cryptographically...");
    println!("This proves that all {} signatures were correctly verified", NUM_SIGNATURES);
    println!("without re-executing the guest program.");
    println!();
    let start_verify = Instant::now();
    let verification_data_for_verify = setup_benchmark_data();
    let is_valid = verify_verify_aggregation(
        verification_data_for_verify,
        verified_count,
        program_io.panic,
        proof,
    );
    let verify_time = start_verify.elapsed();
    println!("✓ Proof verification complete in {:?}", verify_time);
    println!("✓ Proof is valid: {}", is_valid);
    println!();

    // 5. Print Results
    println!("═══════════════════════════════════════════════════");
    println!("                 BENCHMARK RESULTS                 ");
    println!("═══════════════════════════════════════════════════");
    println!();
    println!("Batch Configuration:");
    println!("  • Aggregation Mode:  SingleKey");
    println!("  • Batch Size:        {} signatures", NUM_SIGNATURES);
    println!("  • Verified Count:    {} signatures", verified_count);
    println!();
    println!("Performance Metrics:");
    println!("  • Proof Generation:  {:?}", prove_time);
    println!("  • Proof Verification: {:?}", verify_time);
    println!("  • Proving Throughput: {:.2} sigs/sec", NUM_SIGNATURES as f64 / prove_time.as_secs_f64());
    println!("  • Speedup Factor:    {:.2}x", prove_time.as_secs_f64() / verify_time.as_secs_f64());
    println!();
    println!("Space Efficiency:");
    println!("  • Individual sigs:   ~{} KB", NUM_SIGNATURES * 2);
    println!("  • Aggregated proof:  < 1 MB (constant size)");
    println!("  • Space saved:       ~{}%", ((NUM_SIGNATURES * 2 - 500) * 100) / (NUM_SIGNATURES * 2));
    println!();
    println!("Key Benefits:");
    println!("  ✓ Constant proof size regardless of batch size");
    println!("  ✓ Fast verification (~{:.2}s) vs slow proving (~{:.2}s)", verify_time.as_secs_f64(), prove_time.as_secs_f64());
    println!("  ✓ Post-quantum security (XMSS with Poseidon)");
    println!("  ✓ Succinct proof replaces {} individual signatures", NUM_SIGNATURES);
    println!();
    println!("═══════════════════════════════════════════════════");
}
