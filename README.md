# XMSS Signature Aggregation with Jolt zkVM

Post-quantum signature aggregation system that enables efficient batch verification of XMSS signatures using Jolt zkVM, producing constant-size proofs regardless of batch size.

## Benchmark Results Summary

| Metric                 | Batch Size: 1    | Batch Size: 2    |
|------------------------|------------------|------------------|
| Proof Generation       | 434.95s          | 574.35s          |
| Proof Verification     | 256.79ms         | 300.37ms         |
| Raw signatures| ~2 KB            | ~4 KB            |
| Proof size       | ~650 KB| ~650 KB|

## Quick Start

All commands assume execution from the project root directory.

### Build

```bash
cargo build --release
```

### Test

```bash
# Test root crate
cargo test

# Test Jolt workspace
cargo test --manifest-path src/jolt/Cargo.toml
```

### Run Benchmark

```bash
# Run with default 100 signatures (takes 30-60 seconds for proving)
cargo run --manifest-path src/jolt/Cargo.toml --release

# Run with custom batch size (e.g., 2 signatures for quick testing)
NUM_SIGNATURES_OVERRIDE=2 cargo run --manifest-path src/jolt/Cargo.toml --release

# Use lightweight phony XMSS keys for benchmark-only runs
PHONY_KEYS=1 cargo run --manifest-path src/jolt/Cargo.toml --release
# or pass --phony-keys to the binary for the same behavior
```

> **Warning**
>
> Phony XMSS keys keep the guest logic identical but replace the Merkle path with
> randomized data to speed up dataset generation. They exist **only** for local
> benchmarking; never use this mode for real proofs or security-sensitive runs.

> **Note**
>
> Runs with `NUM_SIGNATURES_OVERRIDE=2` cache the Dory PCS preprocessing bundle
> under `tmp/pcs_preprocessing_small_{strategy}.bin`. The cache is reused only
> when the guest sources and URS file (`dory_urs_33_variables.urs`) are
> unchanged; delete the file or bump the batch size to force regeneration.

Phony and real batches are cached separately under `tmp/benchmark_data_{real|phony}*.bin`
so you can switch between them without accidental reuse.
```
