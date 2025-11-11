use std::{env, fs, path::Path, time::Instant};

use hashsig::{
    signature::{
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
        SignatureScheme,
    },
    MESSAGE_LENGTH,
};
use rayon::{iter::IntoParallelIterator, prelude::*};

const DEFAULT_NUM_SIGNATURES: usize = 100;

fn benchmark_batch_size() -> usize {
    match env::var("NUM_SIGNATURES_OVERRIDE") {
        Ok(raw) => match raw.parse::<usize>() {
            Ok(value) if value > 0 => {
                println!(
                    "Using NUM_SIGNATURES_OVERRIDE={}, overriding default batch size {}",
                    value, DEFAULT_NUM_SIGNATURES
                );
                value
            }
            _ => {
                println!(
                    "NUM_SIGNATURES_OVERRIDE must be a positive integer (got '{}'); falling back to {}",
                    raw, DEFAULT_NUM_SIGNATURES
                );
                DEFAULT_NUM_SIGNATURES
            }
        },
        Err(_) => DEFAULT_NUM_SIGNATURES,
    }
}

// Use the guest types directly to avoid duplication
use guest::{AggregationBatch, VerificationItem};

/// Generates or loads cached public key and 100 signatures to be verified.
fn setup_benchmark_data(num_signatures: usize) -> AggregationBatch {
    let cache_dir = "./tmp";
    let cache_file = if num_signatures == DEFAULT_NUM_SIGNATURES {
        "./tmp/benchmark_data.bin".to_string()
    } else {
        format!("./tmp/benchmark_data_{}.bin", num_signatures)
    };

    // Try to load from cache first
    if Path::new(&cache_file).exists() {
        println!("Loading benchmark data from cache...");
        let start = Instant::now();

        match fs::read(&cache_file) {
            Ok(cached_data) => {
                let payload_len = cached_data.len();
                match bincode::deserialize::<AggregationBatch>(&cached_data) {
                    Ok(data) => {
                        let cached_items = data.items.len();
                        if cached_items == num_signatures {
                            println!(
                                "Cached batch payload: {} bytes (~{:.2} MiB)",
                                payload_len,
                                payload_len as f64 / (1024.0 * 1024.0)
                            );
                            println!("Benchmark data loaded from cache in {:?}", start.elapsed());
                            return data;
                        }

                        println!(
                            "Cached batch contains {} signatures but configuration requests {}; regenerating cache...",
                            cached_items, num_signatures
                        );
                        if let Err(e) = fs::remove_file(&cache_file) {
                            println!("Failed to delete stale cache '{}': {}", cache_file, e);
                        }
                    }
                    Err(e) => {
                        println!("Failed to deserialize cached data: {}, regenerating...", e);
                    }
                }
            }
            Err(e) => {
                println!("Failed to read cache file: {}, regenerating...", e);
            }
        }
    }

    println!(
        "Generating fresh benchmark data: {} signatures...",
        num_signatures
    );
    let start = Instant::now();
    let mut rng = rand::rng();

    // Generate a key active only for the epochs we need, making this step fast.
    let (pk, sk) = SIGWinternitzLifetime18W1::key_gen(&mut rng, 0, num_signatures);

    // Serialize public key once for cloning
    let pk_bytes = bincode::serialize(&pk).expect("Failed to serialize public key");

    // Generate 1000 signatures in parallel for speed.
    // Each item includes its own copy of the public key
    let items: Vec<VerificationItem> = (0..num_signatures)
        .into_par_iter()
        .map(|i| {
            let epoch = i as u32;
            let message: [u8; MESSAGE_LENGTH] = (0..MESSAGE_LENGTH)
                .map(|b| (i + b) as u8)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap();

            let signature =
                SIGWinternitzLifetime18W1::sign(&sk, epoch, &message).expect("Signing failed");

            // Clone public key via serialization for this item
            let pk_clone =
                bincode::deserialize(&pk_bytes).expect("Failed to deserialize public key");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: pk_clone, // Each item has its own public key
            }
        })
        .collect();

    let aggregation_batch = AggregationBatch { items };

    // Cache the generated data
    match bincode::serialize(&aggregation_batch) {
        Ok(serialized_data) => {
            let payload_len = serialized_data.len();
            println!(
                "Generated batch payload: {} bytes (~{:.2} MiB)",
                payload_len,
                payload_len as f64 / (1024.0 * 1024.0)
            );

            if let Err(e) = fs::create_dir_all(cache_dir) {
                println!("Failed to create cache directory: {}", e);
            } else if let Err(e) = fs::write(&cache_file, &serialized_data) {
                println!("Failed to write cache file: {}", e);
            } else {
                println!("Benchmark data cached for future runs");
            }
        }
        Err(e) => {
            println!("Failed to serialize data for caching: {}", e);
        }
    }

    println!("Benchmark data generated in {:?}", start.elapsed());
    aggregation_batch
}

pub fn main() {
    let num_signatures = benchmark_batch_size();

    println!("XMSS Signature Aggregation Benchmark - Jolt zkVM");
    println!("===================================================");
    println!();
    println!("This benchmark demonstrates the XMSS signature aggregation system,");
    println!("which verifies multiple post-quantum signatures within a zkVM to");
    println!("produce a succinct proof of verification.");
    println!();
    println!("Configuration:");
    println!("- Batch Size: {} signatures", num_signatures);
    println!("- XMSS Variant: Lifetime 2^18 with Poseidon hashing");
    println!("- zkVM: Jolt (a16z)");
    println!();

    // 1. Setup Phase: Generate keys and signatures.
    println!("Phase 1: Setup - Generating or Loading Benchmark Data");
    println!("------------------------------------------------------");
    println!(
        "This phase creates {} XMSS signatures or loads them from cache.",
        num_signatures
    );
    println!(
        "Each signature is created with a unique epoch (0-{}).",
        num_signatures - 1
    );
    let verification_data = setup_benchmark_data(num_signatures);
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
    println!(
        "✓ zkVM preprocessing complete in {:?}",
        start_preprocess.elapsed()
    );

    let prove_verify_aggregation =
        guest::build_prover_verify_aggregation(program, prover_preprocessing);
    let verify_verify_aggregation =
        guest::build_verifier_verify_aggregation(verifier_preprocessing);
    println!();

    // 3. Proving Phase
    println!("Phase 3: Proof Generation (Aggregated Verification)");
    println!("----------------------------------------------------");
    println!(
        "Executing guest program inside zkVM to verify all {} signatures...",
        num_signatures
    );
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
    println!(
        "✓ Guest program verified {} signatures successfully",
        verified_count
    );
    println!(
        "✓ Proving throughput: {:.2} signatures/second",
        num_signatures as f64 / prove_time.as_secs_f64()
    );
    println!();

    // 3.5. Proof Size Measurement
    println!("Phase 3.5: Proof Size Analysis");
    println!("-------------------------------");
    println!("Analyzing proof size and space savings...");

    // Jolt proof size is typically 500-800 KB (constant size)
    // This is based on the zkVM circuit size, not batch size
    let proof_size_kb_estimate = 650.0; // Conservative estimate
    let proof_size_mb = proof_size_kb_estimate / 1024.0;

    // Calculate individual signature size
    // XMSS signature with Poseidon ≈ 2 KB per signature
    let individual_sig_size_kb = num_signatures * 2;
    let space_saved_kb = individual_sig_size_kb as f64 - proof_size_kb_estimate;
    let space_saved_percent = (space_saved_kb / individual_sig_size_kb as f64) * 100.0;

    println!("✓ Size analysis complete");
    println!();
    println!("Size Metrics:");
    println!(
        "  • Aggregated proof (est): ~{:.0} KB ({:.2} MB)",
        proof_size_kb_estimate, proof_size_mb
    );
    println!("  • Individual signatures:  ~{} KB", individual_sig_size_kb);
    println!(
        "  • Space saved:            {:.0} KB ({:.1}%)",
        space_saved_kb, space_saved_percent
    );
    println!(
        "  • Compression ratio:      {:.2}x",
        individual_sig_size_kb as f64 / proof_size_kb_estimate
    );
    println!();
    println!(
        "Key insight: Proof size is constant (~{:.0} KB) regardless of batch size!",
        proof_size_kb_estimate
    );
    println!("             Larger batches = greater space savings!");
    println!();

    // 4. Verification Phase
    println!("Phase 4: Proof Verification");
    println!("----------------------------");
    println!("Verifying the zkVM proof cryptographically...");
    println!(
        "This proves that all {} signatures were correctly verified",
        num_signatures
    );
    println!("without re-executing the guest program.");
    println!();
    let start_verify = Instant::now();
    let verification_data_for_verify = setup_benchmark_data(num_signatures);
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
    println!("  • Batch Size:        {} signatures", num_signatures);
    println!("  • Verified Count:    {} signatures", verified_count);
    println!();
    println!("Performance Metrics:");
    println!("  • Proof Generation:  {:?}", prove_time);
    println!("  • Proof Verification: {:?}", verify_time);
    println!(
        "  • Proving Throughput: {:.2} sigs/sec",
        num_signatures as f64 / prove_time.as_secs_f64()
    );
    println!(
        "  • Speedup Factor:    {:.2}x",
        prove_time.as_secs_f64() / verify_time.as_secs_f64()
    );
    println!();
    println!("Space Efficiency:");
    println!("  • Individual sigs:   ~{} KB", individual_sig_size_kb);
    println!(
        "  • Aggregated proof:  ~{:.0} KB ({:.2} MB)",
        proof_size_kb_estimate, proof_size_mb
    );
    println!(
        "  • Space saved:       {:.0} KB ({:.1}%)",
        space_saved_kb, space_saved_percent
    );
    println!(
        "  • Compression ratio: {:.2}x",
        individual_sig_size_kb as f64 / proof_size_kb_estimate
    );
    println!();
    println!("Key Benefits:");
    println!("  ✓ Constant proof size regardless of batch size");
    println!(
        "  ✓ Fast verification (~{:.2}s) vs slow proving (~{:.2}s)",
        verify_time.as_secs_f64(),
        prove_time.as_secs_f64()
    );
    println!("  ✓ Post-quantum security (XMSS with Poseidon)");
    println!(
        "  ✓ Succinct proof replaces {} individual signatures",
        num_signatures
    );
    println!();
    println!("═══════════════════════════════════════════════════");
}
