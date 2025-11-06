# XMSS Signature Aggregation with Jolt zkVM

Post-quantum signature aggregation system that enables efficient batch verification of XMSS signatures using Jolt zkVM, producing constant-size proofs regardless of batch size.


```bash
cargo build
cargo test
# Run Jolt zkVM end-to-end benchmark (1000 signatures)
cargo run --manifest-path src/jolt/Cargo.toml --release
```

Output metrics:
- Proof generation time (~30-60 seconds)
- Proof verification time (~1-2 seconds)
- Throughput (signatures/second)
- Proof size analysis (~650 KB constant size)

**Note:** First run is slower due to compilation. Subsequent runs use cached data at `./tmp/benchmark_data.bin`.

