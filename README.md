# XMSS Signature Aggregation with Jolt zkVM

Post-quantum signature aggregation system that enables efficient batch verification of XMSS signatures using Jolt zkVM, producing constant-size proofs regardless of batch size.


```bash
cargo build
cargo test
# Run Jolt zkVM end-to-end benchmark (default 100 signatures)
cargo run -p jolt --release
```
