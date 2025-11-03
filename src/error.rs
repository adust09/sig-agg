//! Error types for XMSS signature aggregation operations.
//!
//! This module defines comprehensive error handling for the aggregation system,
//! covering validation failures, cryptographic errors, and zkVM system failures.
//!
//! # Error Categories
//!
//! ## Validation Errors
//!
//! Errors that occur during batch validation before zkVM processing:
//! - [`EmptyBatch`](AggregationError::EmptyBatch) - No signatures provided
//! - [`DuplicateEpoch`](AggregationError::DuplicateEpoch) - Same epoch used twice (SingleKey)
//! - [`DuplicateKeyEpochPair`](AggregationError::DuplicateKeyEpochPair) - Same (key, epoch) pair (MultiKey)
//! - [`MissingPublicKey`](AggregationError::MissingPublicKey) - Required public key not provided
//! - [`MismatchedPublicKey`](AggregationError::MismatchedPublicKey) - Public keys don't match
//! - [`BatchTooLarge`](AggregationError::BatchTooLarge) - Batch exceeds zkVM memory limits
//!
//! ## Cryptographic Errors
//!
//! Errors related to signature verification:
//! - [`InvalidSignature`](AggregationError::InvalidSignature) - Signature verification failed
//! - [`VerificationMismatch`](AggregationError::VerificationMismatch) - Wrong number of valid signatures
//! - [`InvalidProof`](AggregationError::InvalidProof) - zkVM proof is invalid
//!
//! ## System Errors
//!
//! Errors from zkVM operations and serialization:
//! - [`SerializationError`](AggregationError::SerializationError) - Failed to serialize/deserialize
//! - [`CompilationError`](AggregationError::CompilationError) - zkVM guest compilation failed
//! - [`ProofGenerationError`](AggregationError::ProofGenerationError) - zkVM proof generation failed
//! - [`ProofVerificationError`](AggregationError::ProofVerificationError) - zkVM proof verification failed
//! - [`MemoryExhausted`](AggregationError::MemoryExhausted) - Out of memory during zkVM execution
//!
//! # Examples
//!
//! ## Handling Validation Errors
//!
//! ```no_run
//! use sig_agg::{aggregate, AggregationMode, AggregationError};
//! # let items = vec![];
//!
//! match aggregate(items, AggregationMode::SingleKey) {
//!     Ok(batch) => println!("Batch created successfully"),
//!     Err(AggregationError::EmptyBatch) => {
//!         eprintln!("Error: At least one signature required");
//!     }
//!     Err(AggregationError::DuplicateEpoch { epoch }) => {
//!         eprintln!("Error: Epoch {} used multiple times", epoch);
//!     }
//!     Err(e) => eprintln!("Aggregation failed: {}", e),
//! }
//! ```
//!
//! ## Error Display
//!
//! All errors implement `Display` and `Error` traits for integration with
//! Rust error handling:
//!
//! ```
//! use sig_agg::AggregationError;
//!
//! let error = AggregationError::EmptyBatch;
//! println!("{}", error);  // "Empty batch: at least one signature required"
//! ```

use std::fmt;

/// Comprehensive error type for aggregation operations.
///
/// All aggregation functions return `Result<T, AggregationError>` to provide
/// detailed error information with context. Each variant includes relevant data
/// to help diagnose and handle the error.
///
/// See the [module documentation](self) for error categories and examples.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AggregationError {
    // Validation errors
    /// Empty batch provided
    EmptyBatch,
    /// Duplicate epoch in SingleKey mode
    DuplicateEpoch { epoch: u32 },
    /// Mismatched public keys in SingleKey mode
    MismatchedPublicKey { expected: String, found: String },
    /// Duplicate (public_key, epoch) pair in MultiKey mode
    DuplicateKeyEpochPair { public_key: String, epoch: u32 },
    /// Missing public key field when required
    MissingPublicKey { mode: String },
    /// Batch size exceeds zkVM memory limits
    BatchTooLarge { size: usize, max: usize },

    // Cryptographic errors
    /// One or more signatures failed verification
    InvalidSignature { index: usize },
    /// Verified count does not match expected count
    VerificationMismatch { expected: usize, actual: usize },
    /// zkVM proof is cryptographically invalid
    InvalidProof,

    // System errors
    /// Serialization failed
    SerializationError { message: String },
    /// zkVM compilation failed
    CompilationError { message: String },
    /// zkVM proof generation failed
    ProofGenerationError { message: String },
    /// zkVM proof verification failed
    ProofVerificationError { message: String },
    /// Memory limit exceeded during execution
    MemoryExhausted { used: usize, limit: usize },
}

impl fmt::Display for AggregationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBatch => write!(f, "Empty batch: at least one signature required"),
            Self::DuplicateEpoch { epoch } => {
                write!(f, "Duplicate epoch {} in SingleKey aggregation mode", epoch)
            }
            Self::MismatchedPublicKey { expected, found } => {
                write!(
                    f,
                    "Mismatched public key: expected {}, found {}",
                    expected, found
                )
            }
            Self::DuplicateKeyEpochPair { public_key, epoch } => {
                write!(
                    f,
                    "Duplicate (public_key, epoch) pair: ({}, {}) in MultiKey mode",
                    public_key, epoch
                )
            }
            Self::MissingPublicKey { mode } => {
                write!(f, "Missing public key in {} mode", mode)
            }
            Self::BatchTooLarge { size, max } => {
                write!(
                    f,
                    "Batch size {} exceeds maximum {} (zkVM memory limit)",
                    size, max
                )
            }
            Self::InvalidSignature { index } => {
                write!(f, "Invalid signature at index {}", index)
            }
            Self::VerificationMismatch { expected, actual } => {
                write!(
                    f,
                    "Verification mismatch: expected {} valid signatures, found {}",
                    expected, actual
                )
            }
            Self::InvalidProof => write!(f, "zkVM proof is cryptographically invalid"),
            Self::SerializationError { message } => {
                write!(f, "Serialization error: {}", message)
            }
            Self::CompilationError { message } => {
                write!(f, "zkVM compilation error: {}", message)
            }
            Self::ProofGenerationError { message } => {
                write!(f, "zkVM proof generation error: {}", message)
            }
            Self::ProofVerificationError { message } => {
                write!(f, "zkVM proof verification error: {}", message)
            }
            Self::MemoryExhausted { used, limit } => {
                write!(
                    f,
                    "Memory exhausted: used {} bytes, limit {} bytes",
                    used, limit
                )
            }
        }
    }
}

impl std::error::Error for AggregationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_batch_error() {
        let error = AggregationError::EmptyBatch;
        assert_eq!(
            error.to_string(),
            "Empty batch: at least one signature required"
        );
    }

    #[test]
    fn test_duplicate_epoch_error() {
        let error = AggregationError::DuplicateEpoch { epoch: 42 };
        assert_eq!(
            error.to_string(),
            "Duplicate epoch 42 in SingleKey aggregation mode"
        );
    }

    #[test]
    fn test_mismatched_public_key_error() {
        let error = AggregationError::MismatchedPublicKey {
            expected: "pk1".to_string(),
            found: "pk2".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "Mismatched public key: expected pk1, found pk2"
        );
    }

    #[test]
    fn test_duplicate_key_epoch_pair_error() {
        let error = AggregationError::DuplicateKeyEpochPair {
            public_key: "pk1".to_string(),
            epoch: 5,
        };
        assert_eq!(
            error.to_string(),
            "Duplicate (public_key, epoch) pair: (pk1, 5) in MultiKey mode"
        );
    }

    #[test]
    fn test_missing_public_key_error() {
        let error = AggregationError::MissingPublicKey {
            mode: "MultiKey".to_string(),
        };
        assert_eq!(error.to_string(), "Missing public key in MultiKey mode");
    }

    #[test]
    fn test_batch_too_large_error() {
        let error = AggregationError::BatchTooLarge {
            size: 10000,
            max: 1000,
        };
        assert_eq!(
            error.to_string(),
            "Batch size 10000 exceeds maximum 1000 (zkVM memory limit)"
        );
    }

    #[test]
    fn test_invalid_signature_error() {
        let error = AggregationError::InvalidSignature { index: 42 };
        assert_eq!(error.to_string(), "Invalid signature at index 42");
    }

    #[test]
    fn test_verification_mismatch_error() {
        let error = AggregationError::VerificationMismatch {
            expected: 100,
            actual: 95,
        };
        assert_eq!(
            error.to_string(),
            "Verification mismatch: expected 100 valid signatures, found 95"
        );
    }

    #[test]
    fn test_invalid_proof_error() {
        let error = AggregationError::InvalidProof;
        assert_eq!(error.to_string(), "zkVM proof is cryptographically invalid");
    }

    #[test]
    fn test_serialization_error() {
        let error = AggregationError::SerializationError {
            message: "invalid format".to_string(),
        };
        assert_eq!(error.to_string(), "Serialization error: invalid format");
    }

    #[test]
    fn test_compilation_error() {
        let error = AggregationError::CompilationError {
            message: "guest build failed".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "zkVM compilation error: guest build failed"
        );
    }

    #[test]
    fn test_proof_generation_error() {
        let error = AggregationError::ProofGenerationError {
            message: "trace too long".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "zkVM proof generation error: trace too long"
        );
    }

    #[test]
    fn test_proof_verification_error() {
        let error = AggregationError::ProofVerificationError {
            message: "invalid proof bytes".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "zkVM proof verification error: invalid proof bytes"
        );
    }

    #[test]
    fn test_memory_exhausted_error() {
        let error = AggregationError::MemoryExhausted {
            used: 15000,
            limit: 10240,
        };
        assert_eq!(
            error.to_string(),
            "Memory exhausted: used 15000 bytes, limit 10240 bytes"
        );
    }

    #[test]
    fn test_error_equality() {
        let error1 = AggregationError::EmptyBatch;
        let error2 = AggregationError::EmptyBatch;
        assert_eq!(error1, error2);

        let error3 = AggregationError::DuplicateEpoch { epoch: 5 };
        let error4 = AggregationError::DuplicateEpoch { epoch: 5 };
        assert_eq!(error3, error4);
    }

    #[test]
    fn test_error_clone() {
        let error = AggregationError::InvalidProof;
        let error_clone = error.clone();
        assert_eq!(error, error_clone);
    }

    #[test]
    fn test_error_debug() {
        let error = AggregationError::EmptyBatch;
        let debug_str = format!("{:?}", error);
        assert!(debug_str.contains("EmptyBatch"));
    }

    #[test]
    fn test_error_trait_implementation() {
        let error: Box<dyn std::error::Error> = Box::new(AggregationError::EmptyBatch);
        assert!(error.to_string().contains("Empty batch"));
    }

    #[test]
    fn test_error_context_data() {
        // Test that errors include relevant context data
        let error = AggregationError::DuplicateEpoch { epoch: 123 };
        match error {
            AggregationError::DuplicateEpoch { epoch } => assert_eq!(epoch, 123),
            _ => panic!("Wrong error variant"),
        }

        let error = AggregationError::BatchTooLarge {
            size: 5000,
            max: 1000,
        };
        match error {
            AggregationError::BatchTooLarge { size, max } => {
                assert_eq!(size, 5000);
                assert_eq!(max, 1000);
            }
            _ => panic!("Wrong error variant"),
        }
    }
}
