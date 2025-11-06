# XMSS Signature Aggregation with Jolt zkVM

Post-quantum signature aggregation system that enables efficient batch verification of XMSS signatures using Jolt zkVM, producing constant-size proofs regardless of batch size.

## Quick Start

### Building

```bash
# Build core library
cargo build

# Build Jolt zkVM benchmark
cargo build --manifest-path src/jolt/Cargo.toml --release
```

### Running Example

```bash
# Run key aggregation example (5 signatures)
cargo run --example key_aggregation
```

### Running Tests

```bash
# Run core library tests
cargo test

# Run Jolt workspace tests
cargo test --manifest-path src/jolt/Cargo.toml
```

### Running Benchmark

```bash
# Run Jolt zkVM end-to-end benchmark (1000 signatures)
cargo run --manifest-path src/jolt/Cargo.toml --release
```

**Output metrics:**
- Proof generation time (~30-60 seconds)
- Proof verification time (~1-2 seconds)
- Throughput (signatures/second)
- Proof size analysis (~650 KB constant size)

**Note:** First run is slower due to compilation. Subsequent runs use cached data at `./tmp/benchmark_data.bin`.

## Features

- **Multi-key aggregation**: Each signature includes its own public key
- **Constant proof size**: ~650 KB regardless of batch size
- **Post-quantum security**: Poseidon-based XMSS signatures
- **Efficient verification**: Single zkVM proof replaces individual signature checks

## Project Structure

```
sig-agg/
├── src/              # Core aggregation library
│   ├── lib.rs        # Public API
│   ├── types.rs      # Data structures
│   ├── aggregator.rs # Validation logic
│   └── error.rs      # Error types
├── src/jolt/         # Jolt zkVM benchmark
│   ├── src/          # Host program
│   ├── guest/        # zkVM guest program
│   └── tests/        # Integration tests
├── examples/         # Usage examples
└── tests/            # Integration and compatibility tests
```

## Development

See [CLAUDE.md](CLAUDE.md) for detailed development guidelines, code conventions, and architecture documentation.
