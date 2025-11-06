//! Key aggregation example
//!
//! This example demonstrates how to aggregate multiple XMSS signatures
//! using the sig-agg library.
//!
//! Run with: `cargo run --example key_aggregation`

use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use sig_agg::{VerificationItem, aggregate};

type XMSSSignature = SIGWinternitzLifetime18W1;

fn main() {
    println!("=== Key Aggregation Example ===\n");

    // Step 1: Generate a keypair
    println!("1. Generating XMSS keypair...");
    let mut rng = rand::rng();
    let (public_key, secret_key) = XMSSSignature::key_gen(&mut rng, 0, 10);
    println!("   ✓ Keypair generated\n");

    // Step 2: Create and sign multiple messages
    println!("2. Creating and signing 5 messages...");
    let mut items = Vec::new();

    for i in 0..5 {
        let epoch = i as u32;
        let message: [u8; MESSAGE_LENGTH] = {
            let mut msg = [0u8; MESSAGE_LENGTH];
            msg[0] = i as u8;
            // Fill rest with pattern for demo purposes
            for j in 1..MESSAGE_LENGTH {
                msg[j] = ((i + j) % 256) as u8;
            }
            msg
        };

        // Sign the message
        let signature =
            XMSSSignature::sign(&secret_key, epoch, &message).expect("Signing should succeed");

        println!("   ✓ Signed message {} at epoch {}", i, epoch);

        // Clone public key for this item
        let pk_bytes = bincode::serialize(&public_key).expect("Serialization should succeed");
        let pk_clone = bincode::deserialize(&pk_bytes).expect("Deserialization should succeed");

        // Create verification item with public key
        items.push(VerificationItem {
            message,
            epoch,
            signature,
            public_key: pk_clone,
        });
    }
    println!();

    // Step 3: Aggregate signatures into a batch
    println!("3. Aggregating signatures...");
    let batch = aggregate(items).expect("Aggregation should succeed");

    println!("   ✓ Created batch with {} signatures", batch.items.len());
    println!("   ✓ Batch is ready for zkVM verification\n");

    // Step 4: Verify batch properties
    println!("4. Batch verification properties:");
    println!("   - Each signature includes its public key");
    println!("   - Each (public_key, epoch) pair is unique");
    println!("   - Batch is ready for zkVM verification\n");

    // Step 5: Serialization (for zkVM input)
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
    println!("\nNext steps:");
    println!("- Pass serialized batch to zkVM guest program");
    println!("- Guest program verifies all signatures");
    println!("- zkVM generates succinct proof");
    println!("- Proof size is constant regardless of batch size");
}
