# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust workspace implementing XMSS signature aggregation and benchmarking within the Jolt zkVM. The root `sig-agg` crate exposes aggregation logic, while `src/jolt/` contains a standalone benchmark binary that verifies 1000 XMSS signatures inside a zero-knowledge proof system.

## Architecture

### Workspace Structure

- **Root crate** (`Cargo.toml`): The `sig-agg` library crate with strict linting and currently empty `src/lib.rs`
- **Jolt benchmark** (`src/jolt/`): Standalone binary workspace with two sub-crates:
  - `src/jolt/src/main.rs`: Host orchestrator that generates signatures, compiles the guest program, produces zkVM proofs, and verifies them
  - `src/jolt/guest/`: Guest crate compiled into the Jolt zkVM program containing the `verify_signatures` function

### Key Dependencies

- **jolt-sdk**: zkVM framework from a16z (features = ["host"])
- **hashsig**: XMSS signature implementation using Poseidon hashing
- **rayon**: Parallel signature generation
- **bincode/serde**: Serialization for caching and zkVM I/O
- **arkworks**: Patched cryptographic primitives (dev/twist-shout branch)

### Data Flow

1. Host generates or loads cached 1000 XMSS signatures (`./tmp/benchmark_data.bin`)
2. Host compiles guest program to `/tmp/jolt-guest-targets`
3. Host passes `VerificationBatch` into guest program for proving
4. Guest verifies signatures inside zkVM and returns count
5. Host verifies the zkVM proof

### Jolt Guest Program

The `#[jolt::provable]` function in `src/jolt/guest/src/lib.rs` defines the computation proven by the zkVM. It takes `AggregationBatch` containing 1000 `VerificationItem`s (each with its own public key for multi-key aggregation), verifies each signature, and returns the count. Memory is configured for 10240 MB with max trace length 65536.

## Development Commands

### Building
```bash
cargo build                                    # Build root crate
cargo build --manifest-path src/jolt/Cargo.toml --release  # Build Jolt benchmark
```

### Testing
```bash
cargo test                                     # Test root crate
cargo test --manifest-path src/jolt/Cargo.toml  # Test Jolt workspace
```

### Linting & Formatting
```bash
cargo fmt                                      # Format with rustfmt.toml settings
cargo clippy --all-targets --all-features      # Run strict lint checks
```

### Running Benchmarks

This project uses **Jolt zkVM end-to-end benchmarks** for performance measurement. Criterion-based micro-benchmarks have been removed as zkVM proof generation (30-60 seconds) is unsuitable for statistical benchmarking.

**Run the benchmark:**
```bash
cargo run --manifest-path src/jolt/Cargo.toml --release
```

This performs:
1. Signature generation (or loads from cache at `./tmp/benchmark_data.bin`)
2. zkVM guest program compilation
3. Proof generation for 1000 XMSS signatures
4. Proof verification

**Output metrics:**
- Proving time (~30-60 seconds)
- Verification time (~1-2 seconds)
- Throughput (signatures/second)
- Proof size analysis (~650 KB constant size)
- Space savings vs individual signatures

**Note:** First run is slower due to compilation; subsequent runs use cached data and compiled guest.

## Code Conventions

- **Edition**: Rust 2024 (root), Rust 2021 (jolt)
- **Formatting**: 4-space indentation, trailing commas in multi-line literals
- **Naming**: `snake_case` for functions/modules, `CamelCase` for types
- **Error handling**: `unused_must_use = deny` — all Results must be handled
- **Linting**: Workspace enables clippy::all, clippy::nursery, and clippy::pedantic with selective allows

## Important Paths

- Build artifacts: `target/`
- Jolt guest compilation cache: `/tmp/jolt-guest-targets`
- Benchmark data cache: `./tmp/benchmark_data.bin`
- Lint configuration: Root `Cargo.toml` [lints] section
- Format configuration: `rustfmt.toml`

## Testing Guidelines

- Unit tests go in `mod tests` blocks within source files
- Integration tests go in `tests/` directory for cross-module coverage
- Host-side tests should handle or stub the `./tmp` cache to remain deterministic
- Run both `cargo test` commands (root and jolt) before submitting changes
- Add regression tests when modifying signature verification or serialization

## Notes

- The project now supports **MultiKey-only** aggregation (SingleKey mode removed)
- Each `VerificationItem` must include its own public key
- Signature generation uses parallelism for speed (rayon)
- Key generation is scoped to required epochs (0 to NUM_SIGNATURES) for efficiency
- Guest program memory/trace settings may need adjustment for different batch sizes
- **Benchmarking**: Use Jolt zkVM benchmark only; Criterion has been removed
- See `AGENTS.md` for additional repository guidelines on structure and workflow
