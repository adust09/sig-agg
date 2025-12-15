## Why
Proof generation benchmarks currently require full XMSS keys, so producing large batches spends significant time building Merkle trees even when we only need performance numbers. leanMultisig’s workflow shows that spoofing Merkle paths for benchmarks drastically shortens setup time without affecting security-critical flows, so we want the same toggle here.

## What Changes
- Add a `KeyMaterialStrategy` toggle (real vs phony) to the benchmark data generator and CLI.
- Implement phony key generation that keeps real WOTS chains but fills Merkle siblings with random digests, mirroring leanMultisig’s approach.
- Separate cache files/log messaging per strategy and document the benchmark-only nature of the phony mode.

## Impact
- Affected specs: benchmark-data-generation (new capability describing benchmark data setup & strategies).
- Affected code: `src/jolt/src/main.rs`, any helper(s) for XMSS keygen/signing, README/AGENTS doc references, tmp cache naming.
