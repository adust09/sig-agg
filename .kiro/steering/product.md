# Product Overview

## Product Description

`sig-agg` is a Rust library and benchmark suite for XMSS (eXtended Merkle Signature Scheme) signature aggregation within zero-knowledge proof systems. The project demonstrates and benchmarks the verification of post-quantum cryptographic signatures inside the Jolt zkVM, enabling privacy-preserving verification of quantum-resistant digital signatures.

## Core Features

- **XMSS Signature Verification in zkVM**: Verify post-quantum XMSS signatures inside zero-knowledge proofs using the Jolt zkVM framework
- **Batch Verification**: Process and verify large batches of signatures (currently 1000 signatures) in a single zkVM proof
- **Performance Benchmarking**: Measure and optimize the performance of signature verification within zero-knowledge environments
- **Poseidon Hashing**: Utilize Poseidon hash function optimized for zero-knowledge circuits
- **Deterministic Caching**: Cache generated signatures and compilation artifacts for faster development iteration
- **Parallel Signature Generation**: Leverage multi-core processors for efficient signature generation using rayon
- **Aggregation Logic Library**: Expose reusable aggregation primitives through the root `sig-agg` crate

## Target Use Case

### Primary Use Cases

1. **Post-Quantum Privacy**: Enable privacy-preserving verification of post-quantum cryptographic signatures without revealing signature details
2. **Batch Signature Verification**: Prove that a large batch of XMSS signatures are valid without requiring verifiers to process each signature individually
3. **zkVM Performance Research**: Benchmark and optimize the performance of cryptographic primitives within zero-knowledge virtual machines
4. **Quantum-Resistant Authentication**: Build systems that combine post-quantum security with zero-knowledge privacy guarantees

### Specific Scenarios

- **Blockchain Scalability**: Aggregate signature verification proofs to reduce on-chain verification costs
- **Privacy-Preserving Audits**: Prove compliance or validation of signed documents without revealing document contents
- **Secure Multi-Party Computation**: Verify authenticated inputs in privacy-preserving computation protocols
- **Post-Quantum ZK Applications**: Research and development of quantum-resistant zero-knowledge proof systems

## Key Value Proposition

### Unique Benefits

1. **Post-Quantum + Zero-Knowledge**: Combines quantum-resistant cryptography (XMSS) with zero-knowledge proofs (Jolt), addressing both quantum threats and privacy requirements
2. **Production-Ready Benchmarking**: Provides real-world performance metrics for XMSS verification in zkVM environments, informing practical deployment decisions
3. **Optimized for zkVM**: Utilizes Poseidon hashing specifically designed for efficient zero-knowledge circuits, rather than traditional hash functions
4. **Developer-Friendly Caching**: Intelligent caching of signatures and build artifacts enables rapid development cycles and experimentation
5. **Modular Architecture**: Separates aggregation logic (library crate) from benchmarking tools (Jolt binary), enabling reuse in different contexts
6. **Parallel Processing**: Leverages modern multi-core systems for efficient signature generation and batch preparation

### Differentiators

- **Focus on Post-Quantum**: Unlike many zkVM projects that use traditional elliptic curve signatures, this project specifically targets quantum-resistant XMSS signatures
- **Transparent Performance**: Open benchmarking of signatures per second and proof generation/verification times
- **Research-Oriented**: Designed to support research into zkVM performance optimization and post-quantum cryptography integration
- **Modern Rust Ecosystem**: Built with cutting-edge Rust tooling (edition 2024, strict linting) and leverages the growing Jolt zkVM ecosystem

### Technical Advantages

- Uses Poseidon hash function which is significantly more efficient in zero-knowledge circuits compared to SHA-256 or other traditional hash functions
- Scoped key generation (only required epochs) minimizes computational overhead
- Configurable memory and trace length settings allow tuning for different batch sizes and performance requirements
- arkworks integration provides robust cryptographic primitives with ongoing development and security research
