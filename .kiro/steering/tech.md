# Technology Stack

## Architecture

### High-Level System Design

The project follows a **dual-workspace architecture** that separates library functionality from benchmarking infrastructure:

1. **Root Workspace** (`sig-agg` crate): Library crate exposing aggregation primitives and utilities
2. **Jolt Workspace** (`src/jolt/`): Standalone benchmark binary with host-guest architecture for zkVM execution

### zkVM Architecture

The Jolt zkVM follows a **host-guest model**:

- **Host** (`src/jolt/src/main.rs`): Orchestrates the zkVM workflow
  - Generates or loads cached XMSS signatures
  - Compiles the guest program
  - Provides inputs to the guest program
  - Generates zkVM proofs
  - Verifies zkVM proofs

- **Guest** (`src/jolt/guest/`): Computation proven inside the zkVM
  - Receives `VerificationBatch` as input
  - Verifies XMSS signatures using Poseidon hashing
  - Returns verification count as output
  - Operates in a constrained environment (no std by default)

### Data Flow

```
Signature Generation → Caching → Guest Compilation → Proof Generation → Proof Verification
         ↓                                                     ↑
    (rayon parallel)                                    (Jolt zkVM)
         ↓                                                     ↑
  benchmark_data.bin ──────────────→ VerificationBatch ───────┘
```

## Language and Runtime

### Rust

- **Root Crate Edition**: Rust 2024 (latest edition with cutting-edge features)
- **Jolt Crates Edition**: Rust 2021 (stable edition for zkVM compatibility)
- **Minimum Version**: Not explicitly specified, but requires recent stable Rust for 2024 edition support

### Key Language Features Used

- **Serde**: Serialization framework for data caching and zkVM I/O
- **Procedural Macros**: `#[jolt::provable]` attribute for guest functions
- **Cargo Workspaces**: Multi-crate organization with dependency sharing
- **Conditional Compilation**: Feature flags for host vs guest builds (`features = ["guest"]`)

## Core Dependencies

### zkVM Framework

- **jolt-sdk** (git: a16z/jolt)
  - Host features: `["host"]` - Full zkVM orchestration capabilities
  - Guest features: `["guest-std"]` - Guest runtime with standard library support
  - Provides zero-knowledge proof generation and verification infrastructure

### Cryptography

- **hashsig** (git: b-wagn/hash-sig)
  - XMSS signature scheme implementation
  - Uses Poseidon hash function (optimized for zero-knowledge circuits)
  - Post-quantum cryptographic primitives
  - Shared between host and guest crates

- **arkworks-algebra** (patched, git: a16z/arkworks-algebra, branch: dev/twist-shout)
  - `ark-ff`: Finite field arithmetic
  - `ark-ec`: Elliptic curve operations
  - `ark-serialize`: Cryptographic serialization
  - `ark-bn254`: BN254 curve implementation
  - Custom patch required for Jolt compatibility

### Parallelism and Performance

- **rayon** (1.8)
  - Parallel signature generation
  - Data-parallel iterators for multi-core processing
  - Used in host-side signature generation only

### Serialization and I/O

- **serde** (1.0)
  - Host: `features = ["derive"]` - Full serialization support
  - Guest: `features = ["derive", "alloc"]`, `default-features = false` - no_std compatible
  - Universal data serialization framework

- **bincode** (1.3)
  - Binary serialization format
  - Used for caching benchmark data
  - Efficient serialization for zkVM inputs/outputs

### Random Number Generation

- **rand** (0.9)
  - Cryptographic randomness for signature generation
  - Used in host-side key and signature generation

## Development Environment

### Required Tools

1. **Rust Toolchain**
   - `rustc` - Rust compiler (supporting edition 2024)
   - `cargo` - Package manager and build system
   - `rustfmt` - Code formatter
   - `clippy` - Linter for code quality

2. **Git**
   - Required for git dependencies (jolt-sdk, hashsig, arkworks)
   - Version control and collaboration

3. **Build Essentials**
   - C compiler (for native dependencies)
   - System libraries for cryptographic operations

### Optional Tools

- **rayon-core**: Automatic thread pool sizing based on available cores
- **benchmarking tools**: For performance analysis beyond built-in benchmarks

## Common Commands

### Build Commands

```bash
# Build root library crate
cargo build

# Build Jolt benchmark (optimized release build)
cargo build --manifest-path src/jolt/Cargo.toml --release

# Clean all build artifacts
cargo clean
```

### Testing Commands

```bash
# Test root crate
cargo test

# Test Jolt workspace (host and guest)
cargo test --manifest-path src/jolt/Cargo.toml
```

### Code Quality Commands

```bash
# Format all code according to rustfmt.toml
cargo fmt

# Run lint checks with strict workspace configuration
cargo clippy --all-targets --all-features

# Check without building (faster)
cargo check
```

### Execution Commands

```bash
# Run Jolt benchmark (generates/verifies zkVM proof)
cargo run --manifest-path src/jolt/Cargo.toml --release

# Run with cargo's verbose output
cargo run --manifest-path src/jolt/Cargo.toml --release --verbose
```

## Environment Variables

### Jolt-Specific Variables

- **Guest Compilation Target**: `/tmp/jolt-guest-targets`
  - Controlled by Jolt SDK
  - Contains compiled guest programs
  - Cached for faster rebuilds

### Rust-Specific Variables

- `RUST_BACKTRACE`: Set to `1` or `full` for detailed error backtraces
- `CARGO_TARGET_DIR`: Override default `target/` directory (optional)
- `RUSTFLAGS`: Additional compiler flags (optional)

## Port Configuration

This project does not run services on network ports. All computation is local:

- No frontend server
- No backend API
- No database connections
- Benchmark runs entirely in-process

## Build Configuration

### Release Profile (Jolt workspace)

Defined in `src/jolt/Cargo.toml`:

```toml
[profile.release]
debug = 1              # Include debug symbols for profiling
codegen-units = 1      # Optimize for performance over compile time
lto = "fat"            # Full link-time optimization
```

### Lint Configuration

Defined in root `Cargo.toml`:

**Rust Lints:**
- `unused_must_use = deny` - All `Result` values must be handled
- `rust_2018_idioms = deny` - Enforce modern Rust patterns
- `unreachable_pub = warn` - Avoid unnecessarily public APIs
- `dead_code = allow` - Development-phase allowance

**Clippy Lints:**
- `all = warn` - Standard lint suite (correctness, suspicious, style, complexity, perf)
- `nursery = warn` - Experimental lints under development
- `pedantic = warn` - Strict style enforcement
- Selective `allow` overrides for overly pedantic checks

### Formatting Configuration

Defined in `src/jolt/rustfmt.toml`:

```toml
reorder_imports = true              # Alphabetize imports
imports_granularity = "Crate"       # Group imports by crate
group_imports = "StdExternalCrate"  # Separate std from external crates
```

**Additional Standards:**
- 4-space indentation (rustfmt default)
- Trailing commas in multi-line literals
- Max line width: 100 characters (rustfmt default)

## Caching and Performance

### Build Artifact Caching

- **Target Directory**: `target/` (Cargo default)
  - Incremental compilation artifacts
  - Dependency builds
  - Binary outputs

- **Guest Compilation Cache**: `/tmp/jolt-guest-targets`
  - Jolt-specific guest program compilation
  - Persists across runs for faster iteration

### Runtime Data Caching

- **Benchmark Data**: `./tmp/benchmark_data.bin`
  - 1000 pre-generated XMSS signatures
  - Public key and verification items
  - Serialized with bincode
  - Regenerated if missing or corrupted

## Guest Program Configuration

Memory and trace settings in `src/jolt/guest/src/lib.rs`:

```rust
#[jolt::provable(
    max_input_size = 10240,  // 10 MB input limit
    max_output_size = 10240, // 10 MB output limit
    memory_size = 10240,     // 10 MB zkVM memory
    max_trace_length = 65536 // Maximum execution trace length
)]
```

These parameters control:
- Maximum size of inputs/outputs to/from guest
- Total memory available in zkVM
- Maximum number of execution steps
- Trade-off between capability and proof generation time

## Architecture Principles

1. **Separation of Concerns**: Library crate vs benchmark infrastructure
2. **Performance-First**: Release builds with LTO and single codegen unit
3. **Strict Safety**: Deny-level lints for must-use results and modern idioms
4. **Deterministic Builds**: Caching for reproducible benchmark iterations
5. **Zero-Knowledge Native**: Design around zkVM constraints (no_std in guest)
6. **Post-Quantum Ready**: XMSS with Poseidon for quantum resistance and zk efficiency
