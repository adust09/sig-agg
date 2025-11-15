# XMSS Signature Aggregation with Jolt zkVM

Post-quantum signature aggregation system that enables efficient batch verification of XMSS signatures using Jolt zkVM, producing constant-size proofs regardless of batch size.

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

Phony and real batches are cached separately under `tmp/benchmark_data_{real|phony}*.bin`
so you can switch between them without accidental reuse.
```

### Clean Cache and Re-run

```bash
# Remove cached URS files and benchmark data
rm -rf dory_urs_*.urs tmp/

# Re-run benchmark (will regenerate caches)
NUM_SIGNATURES_OVERRIDE=2 cargo run --manifest-path src/jolt/Cargo.toml --release
```

## Configuration

- **Batch size**: Set via `NUM_SIGNATURES_OVERRIDE` environment variable (default: 100)
- **Max trace length**: Configured in `src/jolt/guest/src/lib.rs` as `max_trace_length = 33_554_432` (2^25)
- **Memory size**: 8 MB for guest program
- **XMSS variant**: Lifetime 2^18 with Poseidon hashing
