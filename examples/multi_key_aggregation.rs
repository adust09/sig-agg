//! Multi-key aggregation example
//!
//! This example demonstrates how to aggregate XMSS signatures from
//! multiple different public keys using the sig-agg library.
//!
//! Run with: `cargo run --example multi_key_aggregation`

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use sig_agg::{aggregate, AggregationMode, VerificationItem};

type XMSSSignature = SIGWinternitzLifetime18W1;

fn main() {
    println!("=== Multi-Key Aggregation Example ===\n");

    // Step 1: Generate multiple keypairs (simulating different signers)
    println!("1. Generating keypairs for 3 different signers...");
    let mut rng = rand::rng();

    let (pk1, sk1) = XMSSSignature::key_gen(&mut rng, 0, 5);
    println!("   ✓ Signer A keypair generated");

    let (pk2, sk2) = XMSSSignature::key_gen(&mut rng, 0, 5);
    println!("   ✓ Signer B keypair generated");

    let (pk3, sk3) = XMSSSignature::key_gen(&mut rng, 0, 5);
    println!("   ✓ Signer C keypair generated\n");

    // Step 2: Create and sign messages from different signers
    println!("2. Creating signatures from multiple signers...");
    let mut items = Vec::new();

    // Signer A signs 2 messages
    for i in 0..2 {
        let epoch = i as u32;
        let message = create_message(b'A', i);

        let signature = XMSSSignature::sign(&sk1, epoch, &message)
            .expect("Signing should succeed");

        // Clone public key via serialization
        let pk_clone = clone_public_key(&pk1);

        println!("   ✓ Signer A signed message {} at epoch {}", i, epoch);

        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone), // Each item has its own public key
        });
    }

    // Signer B signs 2 messages
    for i in 0..2 {
        let epoch = i as u32;
        let message = create_message(b'B', i);

        let signature = XMSSSignature::sign(&sk2, epoch, &message)
            .expect("Signing should succeed");

        let pk_clone = clone_public_key(&pk2);

        println!("   ✓ Signer B signed message {} at epoch {}", i, epoch);

        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone),
        });
    }

    // Signer C signs 2 messages
    for i in 0..2 {
        let epoch = i as u32;
        let message = create_message(b'C', i);

        let signature = XMSSSignature::sign(&sk3, epoch, &message)
            .expect("Signing should succeed");

        let pk_clone = clone_public_key(&pk3);

        println!("   ✓ Signer C signed message {} at epoch {}", i, epoch);

        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: Some(pk_clone),
        });
    }
    println!();

    // Step 3: Aggregate signatures from all signers
    println!("3. Aggregating signatures from multiple keys...");
    let batch = aggregate(items, AggregationMode::MultiKey)
        .expect("Aggregation should succeed");

    println!("   ✓ Created batch with {} signatures", batch.items.len());
    println!("   ✓ Mode: {:?}", batch.mode);
    println!("   ✓ Signatures from 3 different signers\n");

    // Step 4: Verify batch properties
    println!("4. Batch verification properties:");
    println!("   - Signatures from different public keys");
    println!("   - Each (public_key, epoch) pair is unique");
    println!("   - Same epoch (e.g., 0) can be used by different keys");
    println!("   - Batch is ready for zkVM verification\n");

    // Step 5: Serialization
    println!("5. Serializing batch for zkVM...");
    match bincode::serialize(&batch) {
        Ok(serialized) => {
            println!("   ✓ Batch serialized: {} bytes", serialized.len());
            println!("   ✓ Ready to pass to zkVM guest program\n");
        }
        Err(e) => {
            eprintln!("   ✗ Serialization failed: {}", e);
        }
    }

    println!("=== Example Complete ===");
    println!("\nKey differences from SingleKey mode:");
    println!("- Each item contains its own public key");
    println!("- Different signers can use the same epoch");
    println!("- Batch.public_key is None (keys stored per-item)");
    println!("- Larger serialized size due to multiple public keys");
}

/// Helper function to create a message with a pattern
fn create_message(prefix: u8, index: usize) -> [u8; MESSAGE_LENGTH] {
    let mut msg = [0u8; MESSAGE_LENGTH];
    msg[0] = prefix;
    msg[1] = index as u8;
    // Fill rest with pattern
    for j in 2..MESSAGE_LENGTH {
        msg[j] = ((prefix as usize + index + j) % 256) as u8;
    }
    msg
}

/// Helper function to clone a public key via serialization
fn clone_public_key(
    pk: &<XMSSSignature as SignatureScheme>::PublicKey,
) -> <XMSSSignature as SignatureScheme>::PublicKey {
    let pk_bytes = bincode::serialize(pk).expect("Serialization should succeed");
    bincode::deserialize(&pk_bytes).expect("Deserialization should succeed")
}
