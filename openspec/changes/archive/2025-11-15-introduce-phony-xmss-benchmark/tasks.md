## 1. Planning & Toggle Wiring
- [x] 1.1 Add a `KeyMaterialStrategy` enum plus CLI/env plumbing to select between `Real` and `Phony` (default real). Validate by running `NUM_SIGNATURES_OVERRIDE=2 cargo run ...` with and without the flag and observing the log message toggle.

## 2. Phony Key Generation
- [x] 2.1 Implement the leanMultisig-style fake Merkle path generator that reuses genuine WOTS keys but fabricates Merkle siblings; include serialization helpers so benchmark data remains drop-in compatible. Validate with a unit test that the generated path length equals `LOG_LIFETIME` and that repeated runs with identical seeds are deterministic.

## 3. Benchmark Data & Cache Updates
- [x] 3.1 Teach `setup_benchmark_data` (and cache filenames) to incorporate the key strategy so real/phony batches never mix; emit a conspicuous warning when phony mode is active. Validate by generating both strategies back-to-back and confirming two cache files exist.

## 4. Documentation
- [x] 4.1 Update README/AGENTS instructions with usage guidance, emphasizing that phony mode is benchmark-only. Validate via `rg` search to ensure the warning text appears in README and AGENTS.
