# Requirements Document

## Project Description (Input)
"hash-sigをベースにJoltで証明・検証可能な集約アルゴリズムを実装する"

Translation: "Implement a provable and verifiable aggregation algorithm based on hash-sig in Jolt"

## Introduction

This feature implements a signature aggregation system for XMSS signatures using the hash-sig library within the Jolt zkVM framework. The aggregation algorithm will enable efficient zero-knowledge proofs of batch signature verification by reducing the computational overhead and proof size compared to verifying signatures individually. This provides scalability benefits for post-quantum cryptographic applications while maintaining the security properties of XMSS.

The sig-agg library will expose aggregation primitives that can be used both standalone and within zkVM environments, with particular optimization for Jolt zkVM integration.

## Requirements

### Requirement 1: Signature Aggregation Core Functionality
**Objective:** As a cryptographic application developer, I want to aggregate multiple XMSS signatures into a compact proof structure, so that I can reduce the storage and transmission overhead while maintaining verifiability.

#### Acceptance Criteria

1. WHEN the aggregation system receives multiple valid XMSS signatures with their corresponding public keys and messages THEN the sig-agg library SHALL produce an aggregated proof structure
2. WHEN the aggregation system receives signatures from different public keys THEN the sig-agg library SHALL support multi-key aggregation
3. WHEN the aggregation system receives signatures from the same public key but different epochs THEN the sig-agg library SHALL support single-key batch aggregation
4. IF an aggregated proof is generated from N signatures THEN the sig-agg library SHALL ensure the proof can be verified to confirm all N signatures are valid
5. WHEN an aggregated proof contains at least one invalid signature THEN the verification process SHALL reject the entire aggregated proof
6. IF the aggregation algorithm is applied to XMSS signatures using Poseidon hashing THEN the sig-agg library SHALL maintain compatibility with the hash-sig library's Poseidon-based XMSS implementation

### Requirement 2: Jolt zkVM Integration
**Objective:** As a zero-knowledge application developer, I want to generate and verify aggregated signature proofs within the Jolt zkVM, so that I can efficiently prove the validity of large batches of signatures with reduced computational overhead.

#### Acceptance Criteria

1. WHEN the aggregation system operates within the Jolt zkVM guest environment THEN the guest program SHALL verify aggregated proofs using hash-sig primitives
2. WHEN the host orchestrator prepares inputs for the Jolt guest program THEN the sig-agg library SHALL provide serializable aggregation data structures compatible with Jolt I/O constraints
3. IF the zkVM guest program successfully verifies an aggregated proof THEN the guest program SHALL return a verification result that can be proven in zero-knowledge
4. WHEN generating a zkVM proof of aggregated signature verification THEN the Jolt host SHALL compile the guest program with appropriate memory and trace length configurations for the batch size
5. WHERE the zkVM guest environment has memory constraints THEN the aggregation algorithm SHALL operate within the configurable memory limits (e.g., 10 MB for current configuration)
6. WHEN the aggregated proof verification completes in the guest program THEN the host SHALL be able to verify the zkVM proof to confirm the aggregation was valid

### Requirement 3: Library API Design
**Objective:** As a library consumer, I want a clear and ergonomic API for signature aggregation, so that I can easily integrate aggregation functionality into my application.

#### Acceptance Criteria

1. WHEN a developer uses the sig-agg library THEN the library SHALL expose public API functions for aggregation in `src/lib.rs`
2. WHEN aggregating signatures THEN the sig-agg library SHALL provide a function that accepts a collection of verification items (message, epoch, signature, public key) and returns an aggregated proof
3. WHEN verifying an aggregated proof THEN the sig-agg library SHALL provide a function that accepts the aggregated proof and original verification items and returns a boolean validity result
4. IF aggregation or verification fails due to invalid inputs THEN the sig-agg library SHALL return descriptive error types rather than panicking
5. WHEN using aggregation types and functions THEN the sig-agg library SHALL follow Rust naming conventions (snake_case for functions, CamelCase for types)
6. WHERE the library is used in both std and no_std environments THEN the sig-agg library SHALL support conditional compilation for zkVM guest compatibility
7. WHEN developers inspect aggregation types THEN the sig-agg library SHALL derive appropriate traits (Debug, Clone, Serialize, Deserialize) for public data structures

### Requirement 4: Performance and Scalability
**Objective:** As a performance-conscious developer, I want the aggregation algorithm to be efficient and scalable, so that I can process large signature batches without excessive resource consumption.

#### Acceptance Criteria

1. WHEN aggregating N signatures THEN the aggregation algorithm SHALL have computational complexity better than O(N²)
2. WHEN generating an aggregated proof for 1000 signatures THEN the proof generation SHALL complete within the zkVM trace length limits (e.g., 65536 for current configuration)
3. IF the aggregated proof size is compared to storing N individual signatures THEN the aggregation SHALL provide measurable space savings
4. WHEN the host generates aggregation inputs THEN the sig-agg library SHALL support parallel processing using rayon for multi-core systems
5. WHERE memory is constrained in the zkVM guest THEN the aggregation verification algorithm SHALL use memory efficiently to fit within configured limits
6. WHEN users execute `cargo bench` THEN the benchmark suite SHALL measure and report proof generation time for N aggregated signatures
7. WHEN users execute `cargo bench` THEN the benchmark suite SHALL measure and report proof verification time for N aggregated signatures
8. WHEN users execute `cargo bench` THEN the benchmark suite SHALL measure and report proof size in bytes for N aggregated signatures
9. WHEN users execute `cargo bench` with different batch sizes THEN the benchmark suite SHALL support running benchmarks for various values of N (e.g., 100, 500, 1000 signatures)
10. WHEN benchmarking aggregation performance THEN the Jolt benchmark binary SHALL report aggregation-specific metrics comparing aggregated vs individual signature verification

### Requirement 5: Security and Correctness
**Objective:** As a security-conscious developer, I want the aggregation algorithm to maintain the security properties of XMSS signatures, so that aggregation does not introduce vulnerabilities.

#### Acceptance Criteria

1. WHEN an attacker attempts to forge an aggregated proof without valid signatures THEN the verification SHALL reject the forgery with high probability
2. IF one signature in an aggregated batch is invalid THEN the verification SHALL detect the invalid signature and reject the entire proof
3. WHEN aggregating signatures with mismatched epochs or public keys THEN the aggregation algorithm SHALL enforce consistency checks based on the aggregation mode (single-key vs multi-key)
4. WHERE the aggregation algorithm relies on cryptographic assumptions THEN those assumptions SHALL be consistent with the security guarantees of XMSS and Poseidon hashing
5. WHEN the aggregated proof is generated and verified THEN the system SHALL maintain the post-quantum security properties of the underlying XMSS scheme
6. IF the aggregation involves randomness or nonces THEN the sig-agg library SHALL use cryptographically secure random number generation

### Requirement 6: Testing and Validation
**Objective:** As a quality-focused developer, I want comprehensive tests for the aggregation functionality, so that I can verify correctness and prevent regressions.

#### Acceptance Criteria

1. WHEN the sig-agg library is modified THEN unit tests SHALL verify aggregation and verification functions independently
2. WHEN testing aggregation with the Jolt zkVM THEN integration tests SHALL verify end-to-end proof generation and verification
3. IF aggregation receives invalid inputs (corrupted signatures, mismatched data) THEN tests SHALL verify proper error handling
4. WHEN comparing aggregation performance to individual verification THEN benchmarks SHALL measure and report performance improvements
5. WHERE the hash-sig library provides test vectors THEN the sig-agg library SHALL include tests using those vectors to ensure compatibility
6. WHEN tests are executed THEN both `cargo test` (root crate) and `cargo test --manifest-path src/jolt/Cargo.toml` (Jolt workspace) SHALL pass without failures

### Requirement 7: Documentation and Examples
**Objective:** As a new user of the library, I want clear documentation and examples, so that I can understand how to use the aggregation functionality effectively.

#### Acceptance Criteria

1. WHEN developers read the library documentation THEN public API functions SHALL include Rust doc comments explaining parameters, return values, and usage
2. WHEN users want to see aggregation examples THEN the repository SHALL provide code examples demonstrating basic aggregation workflows
3. IF the aggregation algorithm has specific limitations or constraints THEN the documentation SHALL clearly state these limitations
4. WHEN the Jolt benchmark is executed THEN the output SHALL include explanatory messages about what aggregation operations are being performed
5. WHERE the aggregation API differs between host and guest environments THEN the documentation SHALL explain the differences and provide guidance for each context
