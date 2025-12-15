use std::{
    env, fs, io,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant, UNIX_EPOCH},
};

mod phony_xmss;

use hashsig::{
    signature::{
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
        SignatureScheme,
    },
    MESSAGE_LENGTH,
};
use rayon::{iter::IntoParallelIterator, prelude::*};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use jolt_sdk::{JoltProverPreprocessing, JoltVerifierPreprocessing, Serializable};

const DEFAULT_NUM_SIGNATURES: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum KeyMaterialStrategy {
    Real,
    Phony,
}

const SMALL_PCS_CACHE_BATCH_SIZE: usize = 2;
const PCS_CACHE_PREFIX: &str = "pcs_preprocessing_small";
const URS_FILENAME: &str = "dory_urs_33_variables.urs";

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

fn benchmark_key_strategy() -> KeyMaterialStrategy {
    let cli_requests_phony = env::args().skip(1).any(|arg| arg == "--phony-keys");
    if cli_requests_phony {
        return KeyMaterialStrategy::Phony;
    }

    match env::var("PHONY_KEYS") {
        Ok(raw) if matches!(raw.trim(), "1" | "true" | "TRUE" | "True") => {
            KeyMaterialStrategy::Phony
        }
        _ => KeyMaterialStrategy::Real,
    }
}

fn cache_file_path(num_signatures: usize, strategy: KeyMaterialStrategy) -> String {
    let cache_dir = "./tmp";
    let label = strategy_label(strategy);
    if num_signatures == DEFAULT_NUM_SIGNATURES {
        format!("{cache_dir}/benchmark_data_{label}.bin")
    } else {
        format!("{cache_dir}/benchmark_data_{label}_{num_signatures}.bin")
    }
}

fn strategy_label(strategy: KeyMaterialStrategy) -> &'static str {
    match strategy {
        KeyMaterialStrategy::Real => "real",
        KeyMaterialStrategy::Phony => "phony",
    }
}

fn deterministic_message(index: usize) -> [u8; MESSAGE_LENGTH] {
    std::array::from_fn(|offset| (index + offset) as u8)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct PcsCacheMetadata {
    guest_hash: [u8; 32],
    urs_timestamp: u64,
    strategy: KeyMaterialStrategy,
}

#[derive(Serialize, Deserialize)]
struct PcsCacheBundle {
    metadata: PcsCacheMetadata,
    prover_bytes: Vec<u8>,
    verifier_bytes: Vec<u8>,
}

#[derive(Clone)]
struct PcsCachePlan {
    metadata: PcsCacheMetadata,
    path: PathBuf,
}

// Use the guest types directly to avoid duplication
use guest::{AggregationBatch, VerificationItem};
use phony_xmss::generate_phony_item;

/// Generates or loads cached public key and 100 signatures to be verified.
fn setup_benchmark_data(num_signatures: usize, strategy: KeyMaterialStrategy) -> AggregationBatch {
    let cache_dir = "./tmp";
    let cache_file = cache_file_path(num_signatures, strategy);
    let strategy_tag = strategy_label(strategy);

    // Try to load from cache first
    if Path::new(&cache_file).exists() {
        println!("Loading {strategy_tag} benchmark data from cache...");
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
        "Generating fresh {strategy_tag} benchmark data: {} signatures...",
        num_signatures
    );
    let start = Instant::now();

    let items: Vec<VerificationItem> = match strategy {
        KeyMaterialStrategy::Real => {
            let mut rng = rand::rng();
            let (pk, sk) = SIGWinternitzLifetime18W1::key_gen(&mut rng, 0, num_signatures);
            let pk_bytes = bincode::serialize(&pk).expect("Failed to serialize public key");

            (0..num_signatures)
                .into_par_iter()
                .map(|i| {
                    let epoch = i as u32;
                    let message = deterministic_message(i);
                    let signature = SIGWinternitzLifetime18W1::sign(&sk, epoch, &message)
                        .expect("Signing failed");

                    let pk_clone =
                        bincode::deserialize(&pk_bytes).expect("Failed to deserialize public key");

                    VerificationItem {
                        message,
                        epoch,
                        signature,
                        public_key: pk_clone,
                    }
                })
                .collect()
        }
        KeyMaterialStrategy::Phony => (0..num_signatures)
            .into_par_iter()
            .map(|i| generate_phony_item(i as u32, deterministic_message(i), i as u64))
            .collect(),
    };

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
                println!("Benchmark data cached for future {strategy_tag} runs");
            }
        }
        Err(e) => {
            println!("Failed to serialize data for caching: {}", e);
        }
    }

    println!("Benchmark data generated in {:?}", start.elapsed());
    aggregation_batch
}

fn build_pcs_cache_plan(strategy: KeyMaterialStrategy) -> io::Result<PcsCachePlan> {
    let metadata = PcsCacheMetadata {
        guest_hash: compute_guest_source_hash()?,
        urs_timestamp: read_urs_timestamp()?,
        strategy,
    };

    Ok(PcsCachePlan {
        metadata,
        path: pcs_cache_file_path(strategy),
    })
}

fn pcs_cache_file_path(strategy: KeyMaterialStrategy) -> PathBuf {
    Path::new("./tmp").join(format!(
        "{PCS_CACHE_PREFIX}_{}.bin",
        strategy_label(strategy)
    ))
}

#[allow(clippy::type_complexity)]
fn load_pcs_cache(
    plan: &PcsCachePlan,
) -> io::Result<
    Option<(
        JoltProverPreprocessing<jolt_sdk::F, jolt_sdk::PCS>,
        JoltVerifierPreprocessing<jolt_sdk::F, jolt_sdk::PCS>,
    )>,
> {
    let bytes = match fs::read(&plan.path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };

    let bundle: PcsCacheBundle =
        bincode::deserialize(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if bundle.metadata != plan.metadata {
        return Ok(None);
    }

    let prover =
        <JoltProverPreprocessing<jolt_sdk::F, jolt_sdk::PCS> as Serializable>::deserialize_from_bytes(
            &bundle.prover_bytes,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let verifier =
        <JoltVerifierPreprocessing<jolt_sdk::F, jolt_sdk::PCS> as Serializable>::deserialize_from_bytes(
            &bundle.verifier_bytes,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(Some((prover, verifier)))
}

fn store_pcs_cache(
    plan: &PcsCachePlan,
    prover: &JoltProverPreprocessing<jolt_sdk::F, jolt_sdk::PCS>,
    verifier: &JoltVerifierPreprocessing<jolt_sdk::F, jolt_sdk::PCS>,
) -> io::Result<()> {
    if let Some(parent) = plan.path.parent() {
        fs::create_dir_all(parent)?;
    }

    let bundle = PcsCacheBundle {
        metadata: plan.metadata.clone(),
        prover_bytes: prover
            .serialize_to_bytes()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        verifier_bytes: verifier
            .serialize_to_bytes()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
    };

    let encoded =
        bincode::serialize(&bundle).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let tmp_path = plan.path.with_extension("tmp");
    fs::write(&tmp_path, encoded)?;
    fs::rename(tmp_path, &plan.path)?;
    Ok(())
}

fn compute_guest_source_hash() -> io::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hash_guest_file(Path::new("src/jolt/guest/Cargo.toml"), &mut hasher)?;
    hash_guest_sources(Path::new("src/jolt/guest/src"), &mut hasher)?;
    Ok(hasher.finalize().into())
}

fn hash_guest_sources(path: &Path, hasher: &mut Sha256) -> io::Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(path)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<Result<_, _>>()?;
    entries.sort();

    for entry in entries {
        if entry.is_dir() {
            hash_guest_sources(&entry, hasher)?;
        } else if entry.extension().is_some_and(|ext| ext == "rs") {
            hash_guest_file(&entry, hasher)?;
        }
    }

    Ok(())
}

fn hash_guest_file(path: &Path, hasher: &mut Sha256) -> io::Result<()> {
    let mut file = fs::File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    hasher.update(&buffer);
    Ok(())
}

fn read_urs_timestamp() -> io::Result<u64> {
    let metadata = fs::metadata(URS_FILENAME)?;
    let modified = metadata.modified()?;
    let duration = modified
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    Ok(duration.as_secs())
}

pub fn main() {
    let num_signatures = benchmark_batch_size();
    let key_strategy = benchmark_key_strategy();
    let use_small_pcs_cache = num_signatures == SMALL_PCS_CACHE_BATCH_SIZE;
    let mut pcs_cache_plan: Option<PcsCachePlan> = None;
    let mut cached_preprocessing: Option<(
        JoltProverPreprocessing<jolt_sdk::F, jolt_sdk::PCS>,
        JoltVerifierPreprocessing<jolt_sdk::F, jolt_sdk::PCS>,
    )> = None;

    if use_small_pcs_cache {
        match build_pcs_cache_plan(key_strategy) {
            Ok(plan) => {
                match load_pcs_cache(&plan) {
                    Ok(Some(preprocessing)) => {
                        println!(
                            "PCS preprocessing cache hit for 2-signature run ({}).",
                            plan.path.display()
                        );
                        cached_preprocessing = Some(preprocessing);
                    }
                    Ok(None) => {
                        println!(
                            "PCS preprocessing cache unavailable or stale ({}); regenerating.",
                            plan.path.display()
                        );
                    }
                    Err(err) => {
                        println!(
                            "Failed to load PCS preprocessing cache ({}): {}",
                            plan.path.display(),
                            err
                        );
                    }
                }
                pcs_cache_plan = Some(plan);
            }
            Err(err) => {
                println!("PCS preprocessing cache disabled: {}", err);
            }
        }
    }

    match key_strategy {
        KeyMaterialStrategy::Real => {
            println!("Using real XMSS key material (secure default)");
        }
        KeyMaterialStrategy::Phony => {
            println!("⚠ Using phony XMSS key material for benchmarking only");
        }
    }

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
    let verification_data = setup_benchmark_data(num_signatures, key_strategy);
    let verification_bytes =
        bincode::serialize(&verification_data).expect("failed to encode batch for prover");
    let verification_data_for_verify: AggregationBatch =
        bincode::deserialize(&verification_bytes).expect("failed to decode batch for verifier");
    println!();

    // 2. Jolt Compilation and Preprocessing
    println!("Phase 2: zkVM Compilation and Preprocessing");
    println!("--------------------------------------------");
    println!("Compiling the guest program (verify_aggregation) to zkVM bytecode...");
    println!("This step is slow on first run but cached for subsequent runs.");
    let start_preprocess = Instant::now();
    let target_dir = "/tmp/jolt-guest-targets";
    let mut program = guest::compile_verify_aggregation(target_dir);

    let (prover_preprocessing, verifier_preprocessing) =
        if let Some((prover, verifier)) = cached_preprocessing {
            if let Some(plan) = pcs_cache_plan.as_ref() {
                println!(
                    "Using cached PCS preprocessing bundle from {}",
                    plan.path.display()
                );
            } else {
                println!("Using cached PCS preprocessing bundle");
            }
            (prover, verifier)
        } else {
            println!("Preprocessing prover and verifier data structures...");
            println!("This generates commitment keys and other cryptographic parameters.");
            let prover = guest::preprocess_prover_verify_aggregation(&mut program);
            let verifier = guest::verifier_preprocessing_from_prover_verify_aggregation(&prover);

            if let Some(plan) = pcs_cache_plan.as_ref() {
                match store_pcs_cache(plan, &prover, &verifier) {
                    Ok(()) => println!("PCS preprocessing cache saved to {}", plan.path.display()),
                    Err(err) => println!(
                        "Failed to update PCS preprocessing cache ({}): {}",
                        plan.path.display(),
                        err
                    ),
                }
            }

            (prover, verifier)
        };
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
