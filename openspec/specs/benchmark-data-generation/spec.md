# benchmark-data-generation Specification

## Purpose
TBD - created by archiving change introduce-phony-xmss-benchmark. Update Purpose after archive.
## Requirements
### Requirement: Benchmark key material strategies
The benchmark data generator SHALL accept a `KeyMaterialStrategy` (default `Real`) that determines how XMSS keys are created before running the Jolt host benchmarks.

#### Scenario: Default real keys
- **GIVEN** the benchmark is invoked without overrides
- **WHEN** the data generator produces a batch
- **THEN** it MUST use the existing secure XMSS key generation path and MUST log that the real strategy is in use

#### Scenario: Phony keys via flag
- **GIVEN** the `PHONY_KEYS` env var or `--phony-keys` CLI flag is provided
- **WHEN** the benchmark runs
- **THEN** it SHALL switch to the `Phony` strategy and emit a conspicuous warning that this mode is benchmark-only

### Requirement: Phony XMSS strategy implementation
The `Phony` strategy SHALL reuse genuine WOTS key material while fabricating Merkle siblings with random digests so that proofs exercise the same guest logic without incurring real Merkle construction cost.

#### Scenario: Merkle fabrication
- **WHEN** the phony strategy generates a signature
- **THEN** it SHALL sample `LOG_LIFETIME` sibling hashes according to the epoch's left/right bit pattern, store them with the signature, and compute the fake root by hashing upward with Poseidon16

#### Scenario: Deterministic signing per seed
- **WHEN** the random number generator is seeded identically for reproducible benchmarks
- **THEN** phony key generation SHALL produce identical outputs for the same signature index so cache hits remain valid

### Requirement: Strategy-specific caching & documentation
Benchmark caches and docs SHALL distinguish between real and phony strategies to avoid accidental reuse.

#### Scenario: Cache separation
- **WHEN** the benchmark writes cache files
- **THEN** the filename (and optional metadata) SHALL include the strategy name so loading real data while in phony mode is prevented

#### Scenario: Documentation warning
- **WHEN** developers read the README/AGENTS usage section
- **THEN** they SHALL see explicit guidance that phony XMSS keys are for benchmarking only and MUST NOT be used for production proofs

