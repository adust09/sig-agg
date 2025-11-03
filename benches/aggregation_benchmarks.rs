//! Criterion benchmarks for XMSS signature aggregation
//!
//! These benchmarks measure the performance of the aggregation library,
//! including validation, batch construction, and baseline comparisons.
//!
//! Note: zkVM proof generation/verification benchmarks are excluded from
//! Criterion due to their long execution time (30-60 seconds each).
//! Those are measured in the main benchmark binary (src/jolt/src/main.rs).

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hashsig::{
    MESSAGE_LENGTH,
    signature::{
        SignatureScheme,
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
    },
};
use sig_agg::{aggregate, AggregationMode, VerificationItem};
use std::sync::OnceLock;

type XMSSSignature = SIGWinternitzLifetime18W1;

// Shared keypair for benchmarks to avoid expensive key generation
static KEYPAIR: OnceLock<(
    <XMSSSignature as SignatureScheme>::PublicKey,
    <XMSSSignature as SignatureScheme>::SecretKey,
)> = OnceLock::new();

fn get_keypair() -> &'static (
    <XMSSSignature as SignatureScheme>::PublicKey,
    <XMSSSignature as SignatureScheme>::SecretKey,
) {
    KEYPAIR.get_or_init(|| {
        let mut rng = rand::rng();
        XMSSSignature::key_gen(&mut rng, 0, 1100)
    })
}

/// Generate verification items for benchmarking
fn generate_items(count: usize, include_pk: bool) -> Vec<VerificationItem> {
    let (_pk, sk) = get_keypair();

    (0..count)
        .map(|i| {
            let epoch = i as u32;
            let message = [epoch as u8; MESSAGE_LENGTH];
            let signature = XMSSSignature::sign(sk, epoch, &message)
                .expect("Signing should succeed");

            VerificationItem {
                message,
                epoch,
                signature,
                public_key: if include_pk {
                    let (pk, _) = get_keypair();
                    let pk_bytes = bincode::serialize(pk).unwrap();
                    Some(bincode::deserialize(&pk_bytes).unwrap())
                } else {
                    None
                },
            }
        })
        .collect()
}

/// Benchmark: Aggregation validation (SingleKey mode)
fn bench_aggregation_single_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregation_single_key");

    for size in [10, 50, 100, 500, 1000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let items = generate_items(size, false);
                black_box(aggregate(items, AggregationMode::SingleKey))
                    .expect("Aggregation should succeed")
            });
        });
    }

    group.finish();
}

/// Benchmark: Aggregation validation (MultiKey mode)
fn bench_aggregation_multi_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregation_multi_key");

    for size in [10, 50, 100, 500, 1000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| {
                let items = generate_items(size, true);
                black_box(aggregate(items, AggregationMode::MultiKey))
                    .expect("Aggregation should succeed")
            });
        });
    }

    group.finish();
}

/// Benchmark: Baseline - Individual signature verification
fn bench_baseline_individual_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("baseline_individual_verification");

    for size in [10, 50, 100, 500, 1000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let items = generate_items(size, false);
            let (pk, _) = get_keypair();

            b.iter(|| {
                let mut verified_count = 0;
                for item in &items {
                    if XMSSSignature::verify(
                        black_box(pk),
                        black_box(item.epoch),
                        black_box(&item.message),
                        black_box(&item.signature),
                    ) {
                        verified_count += 1;
                    }
                }
                black_box(verified_count)
            });
        });
    }

    group.finish();
}

/// Benchmark: Batch serialization size
fn bench_batch_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_serialization");

    for size in [10, 50, 100, 500, 1000] {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let items = generate_items(size, false);
            let batch = aggregate(items, AggregationMode::SingleKey)
                .expect("Aggregation should succeed");

            b.iter(|| {
                let serialized = black_box(bincode::serialize(&batch))
                    .expect("Serialization should succeed");
                black_box(serialized.len())
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets =
        bench_aggregation_single_key,
        bench_aggregation_multi_key,
        bench_baseline_individual_verification,
        bench_batch_serialization,
}

criterion_main!(benches);
