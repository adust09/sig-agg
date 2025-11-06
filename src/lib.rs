//! XMSS Signature Aggregation Library
//!
//! This library provides aggregation primitives for XMSS (eXtended Merkle Signature Scheme)
//! signatures using zkVM-based succinct arguments via the Jolt framework.
//!
//! # Overview
//!
//! The `sig-agg` library enables efficient batch verification of post-quantum XMSS signatures
//! through zero-knowledge proofs. Signatures from different signers can be aggregated into
//! a single batch for efficient verification.
//!
//! # Validation Rules
//!
//! Each (public_key, epoch) combination must be unique within a batch to prevent XMSS signature
//! reuse attacks.
//!
//! # Example
//!
//! ```no_run
//! use sig_agg::{aggregate, VerificationItem};
//!
//! // Create verification items (signatures with their context)
//! let items: Vec<VerificationItem> = vec![/* ... */];
//!
//! // Aggregate signatures
//! let batch = aggregate(items)
//!     .expect("Aggregation failed");
//!
//! // The batch can now be verified in a zkVM environment
//! ```
//!
//! # Features
//!
//! - Post-quantum signature aggregation (XMSS with Poseidon hashing)
//! - Batch verification in zkVM (Jolt)
//! - O(N) aggregation complexity
//! - Comprehensive error handling
//! - Serialization support for zkVM I/O

pub mod aggregator;
pub mod error;
pub mod types;

// Re-export commonly used types and functions for convenience
pub use aggregator::{aggregate, validate};
pub use error::AggregationError;
pub use types::{AggregationBatch, AggregationProof, ProofMetadata, VerificationItem};
