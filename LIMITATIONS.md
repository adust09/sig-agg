# Limitations and Constraints

This document describes the limitations, constraints, and performance characteristics of the XMSS signature aggregation system.

## Table of Contents

1. [Batch Size Constraints](#batch-size-constraints)
2. [zkVM Memory Requirements](#zkvm-memory-requirements)
3. [zkVM Configuration Parameters](#zkvm-configuration-parameters)
4. [Performance Characteristics](#performance-characteristics)
5. [Security Limitations](#security-limitations)
6. [Platform Requirements](#platform-requirements)

---

## Batch Size Constraints

### Maximum Batch Size

The maximum number of signatures that can be aggregated in a single batch is constrained by:

1. **zkVM Memory Limit**: 10 MB (10240 MB configured in guest program)
2. **zkVM Trace Length**: 65536 maximum trace entries

**Practical Limits:**
- **Tested batch size**: 1000 signatures (verified in integration tests and benchmarks)
- **Estimated maximum**: ~5000 signatures per batch (dependent on XMSS parameter set)
- **Memory per signature**: Approximately 2-3 KB (varies with Poseidon parameter set)

### Batch Size Recommendations

| Batch Size | Proof Time Estimate | Use Case |
|------------|---------------------|----------|
| 10-100     | < 10 seconds       | Testing, small-scale applications |
| 100-500    | 10-30 seconds      | Medium-scale applications |
| 500-1000   | 30-60 seconds      | Production batches (recommended) |
| 1000-5000  | 1-5 minutes        | Large batches (experimental) |

**Note**: Exceeding memory limits will result in `AggregationError::MemoryExhausted` or zkVM execution failure.

---

## zkVM Memory Requirements

### Guest Program Memory Configuration

The zkVM guest program is configured with the following memory settings:

```rust
#[jolt::provable(memory_size = 10240, max_trace_length = 65536)]
fn verify_aggregation(batch: AggregationBatch) -> u32 { ... }
```

### Memory Breakdown

For a batch of N signatures:

```
Total Memory = Base Memory + (N * Per-Signature Memory)

Where:
- Base Memory ≈ 100 KB (zkVM runtime + stack)
- Per-Signature Memory ≈ 2-3 KB (signature + message + public key)
```

**Example** (1000 signatures):
```
100 KB + (1000 * 2.5 KB) = 100 KB + 2500 KB ≈ 2.6 MB
```

### Memory Optimization Tips

1. **SingleKey mode**: Use when possible to reduce memory (shared public key stored once)
2. **Batch splitting**: Split large batches into multiple smaller batches
3. **Message compression**: Consider message hashing before aggregation if messages are large

---

## zkVM Configuration Parameters

### Guest Program Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `memory_size` | 10240 (10 MB) | Maximum memory available to guest program |
| `max_trace_length` | 65536 | Maximum number of execution trace entries |

### Modifying Parameters

To adjust limits for larger batches, modify the `#[jolt::provable]` attribute in `src/jolt/guest/src/lib.rs`:

```rust
#[jolt::provable(memory_size = 20480, max_trace_length = 131072)]  // 20 MB, 128K trace
fn verify_aggregation(batch: AggregationBatch) -> u32 { ... }
```

**Trade-offs:**
- ✅ Higher limits → larger batches supported
- ❌ Higher limits → longer preprocessing time
- ❌ Higher limits → increased proof generation time
- ❌ Higher limits → larger proof size

---

## Performance Characteristics

### Time Complexity

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Batch validation | O(N) | Linear in number of signatures |
| Aggregation | O(N) | Hash set operations for uniqueness checking |
| zkVM proof generation | O(N * log N) | Dominated by signature verification in zkVM |
| zkVM proof verification | O(1) | Constant time (independent of batch size) |

### Space Complexity

| Component | Size | Scaling |
|-----------|------|---------|
| Individual signature | ~2 KB | O(N) total for N signatures |
| Aggregation batch | ~2-3 KB * N | O(N) |
| zkVM proof | ~200-800 KB | O(1) - constant regardless of N |

**Space Savings:**

For N signatures:
```
Individual storage: N * 2 KB
Aggregated proof: ~500 KB (constant)

Savings for 1000 sigs:
Individual: 1000 * 2 KB = 2000 KB
Aggregated: ~500 KB
Reduction: ~75% space saved
```

### Benchmark Results

Based on testing with 1000 signatures (SingleKey mode):

| Metric | Value | Notes |
|--------|-------|-------|
| Proof generation time | ~30-60 seconds | Varies by CPU |
| Proof verification time | < 5 seconds | Fast verification |
| Proof size | < 1 MB | Constant size |
| Throughput | ~15-30 sigs/sec | During proof generation |

**Hardware tested:**
- CPU: Modern x86_64 processor
- RAM: 16 GB minimum recommended
- Storage: SSD recommended for caching

---

## Security Limitations

### XMSS Epoch Constraints

**Critical Security Requirement:**
- Each XMSS epoch can only be used **once per public key**
- Reusing an epoch compromises the security of the XMSS signature scheme

**Enforcement:**
- `SingleKey` mode: Validates epoch uniqueness across batch
- `MultiKey` mode: Validates (public_key, epoch) pair uniqueness

**Violation Consequences:**
```rust
// This will return AggregationError::DuplicateEpoch
let items = vec![
    item_with_epoch_0,
    item_with_epoch_0,  // ❌ Same epoch twice!
];
aggregate(items, AggregationMode::SingleKey)?;
```

### Cryptographic Assumptions

The security of this system relies on:

1. **XMSS Security**: Hash-based signatures using Poseidon hash function
2. **zkVM Security**: Jolt proving system security assumptions
3. **Poseidon Hash Security**: Collision resistance and preimage resistance

### Limitations

1. **No Signature Revocation**: Once a proof is generated, it cannot be revoked
2. **No Timestamp Verification**: Proof does not encode when signatures were created
3. **Batch Integrity**: The entire batch must be valid; partial verification is not supported
4. **Public Inputs**: Batch data is public (not hidden by zkVM proof)

---

## Platform Requirements

### Supported Platforms

| Platform | Support Level | Notes |
|----------|---------------|-------|
| Linux x86_64 | ✅ Full | Primary development platform |
| macOS ARM64 | ✅ Full | Tested on Apple Silicon |
| macOS x86_64 | ✅ Full | Tested on Intel Macs |
| Windows | ⚠️ Limited | May require WSL for zkVM |

### Dependencies

**Rust:**
- Minimum version: 1.75.0 (Rust 2024 edition)
- Recommended: Latest stable

**System:**
- RAM: 16 GB minimum (32 GB recommended for large batches)
- Storage: 10 GB free space (for zkVM compilation artifacts)
- CPU: Multi-core processor recommended (proof generation is CPU-intensive)

### Build Requirements

1. **Jolt zkVM Target**: Requires `/tmp/jolt-guest-targets` directory for compilation cache
2. **Benchmark Cache**: Uses `./tmp/benchmark_data.bin` for signature caching
3. **Internet**: Required for initial dependency download

---

## Known Issues

### Performance

1. **First Compilation Slow**: Initial guest program compilation takes 3-5 minutes
   - **Workaround**: Subsequent builds are faster due to caching

2. **Large Batch Memory**: Batches > 1000 signatures may exceed memory limits
   - **Workaround**: Split into multiple smaller batches

### Compatibility

1. **Debug Trait**: `VerificationItem` and `AggregationBatch` do not implement `Debug`
   - **Reason**: Underlying hash-sig types don't implement Debug
   - **Impact**: Cannot use `{:?}` formatting or `dbg!()` macro

2. **no_std Support**: Currently requires `std` library
   - **Reason**: zkVM host operations require standard library
   - **Future**: Guest program could be made `no_std` compatible

---

## Future Improvements

### Performance

- [ ] Parallel signature verification in zkVM (if supported by Jolt)
- [ ] Optimized serialization format for reduced batch size
- [ ] Incremental proof generation for very large batches

### Features

- [ ] Partial batch verification
- [ ] Signature revocation support
- [ ] Timestamp inclusion in proofs
- [ ] Proof compression for smaller artifacts

### Platform

- [ ] Windows native support (without WSL)
- [ ] `no_std` support for embedded systems
- [ ] WASM compilation target

---

## Support and Contact

For questions about limitations or to report issues:

- **Issues**: Open an issue on the project repository
- **Documentation**: See `README.md` and `CLAUDE.md` for additional context
- **Examples**: Run `cargo run --example <name>` for usage demonstrations

---

**Last Updated**: 2025-11-03
