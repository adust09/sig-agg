use std::{convert::TryInto, sync::OnceLock};

use bincode;
use guest::VerificationItem;
use hashsig::{
    signature::{
        generalized_xmss::instantiations_poseidon::lifetime_2_to_the_18::winternitz::SIGWinternitzLifetime18W1,
        SignatureScheme,
    },
    MESSAGE_LENGTH, TWEAK_SEPARATOR_FOR_CHAIN_HASH, TWEAK_SEPARATOR_FOR_MESSAGE_HASH,
    TWEAK_SEPARATOR_FOR_TREE_HASH,
};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_koala_bear::{
    default_koalabear_poseidon2_16, default_koalabear_poseidon2_24, KoalaBear, Poseidon2KoalaBear,
};
use p3_symmetric::Permutation;
use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

const PARAMETER_LEN: usize = 5;
const HASH_LEN_FE: usize = 7;
const MSG_LEN_FE: usize = 9;
const TWEAK_LEN_FE: usize = 2;
const RAND_LEN: usize = 5;
const CHUNK_SIZE_W1: usize = 1;
const BASE_W1: usize = 2;
const NUM_CHUNKS_W1: usize = 155;
const NUM_CHUNKS_CHECKSUM_W1: usize = 8;
const NUM_CHAINS: usize = NUM_CHUNKS_W1 + NUM_CHUNKS_CHECKSUM_W1;
const CHAIN_LENGTH: usize = BASE_W1;
const LOG_LIFETIME: usize = 32;

pub(crate) fn generate_phony_item(
    epoch: u32,
    message: [u8; MESSAGE_LENGTH],
    seed: u64,
) -> VerificationItem {
    let mut rng = StdRng::seed_from_u64(seed);

    let parameter: [KoalaBear; PARAMETER_LEN] = rng.random();
    let rho: [KoalaBear; RAND_LEN] = rng.random();

    let encoding = winternitz_encode(&parameter, epoch, &rho, &message);

    let (hashes, chain_ends) = build_wots_hashes(&mut rng, &parameter, epoch, &encoding);

    let (co_path, root) = build_merkle_path(&mut rng, &parameter, epoch, &chain_ends);

    let public_key = deserialize_public_key(RawPublicKey { root, parameter });
    let signature = deserialize_signature(RawSignature {
        path: RawHashTreeOpening { co_path },
        rho,
        hashes,
    });

    VerificationItem {
        message,
        epoch,
        signature,
        public_key,
    }
}

#[derive(Serialize, Deserialize)]
struct RawHashTreeOpening {
    co_path: Vec<Digest>,
}

#[derive(Serialize, Deserialize)]
struct RawSignature {
    path: RawHashTreeOpening,
    rho: [KoalaBear; RAND_LEN],
    hashes: Vec<Digest>,
}

#[derive(Serialize, Deserialize)]
struct RawPublicKey {
    root: Digest,
    parameter: [KoalaBear; PARAMETER_LEN],
}

type Digest = [KoalaBear; HASH_LEN_FE];

type PublicKey = <SIGWinternitzLifetime18W1 as SignatureScheme>::PublicKey;
type Signature = <SIGWinternitzLifetime18W1 as SignatureScheme>::Signature;

fn deserialize_signature(raw: RawSignature) -> Signature {
    let bytes = bincode::serialize(&raw).expect("failed to serialize phony signature");
    bincode::deserialize(&bytes).expect("failed to deserialize phony signature")
}

#[cfg(test)]
fn serialize_signature(sig: &Signature) -> RawSignature {
    let bytes = bincode::serialize(sig).expect("failed to serialize signature");
    bincode::deserialize(&bytes).expect("failed to deserialize raw signature")
}

fn deserialize_public_key(raw: RawPublicKey) -> PublicKey {
    let bytes = bincode::serialize(&raw).expect("failed to serialize phony public key");
    bincode::deserialize(&bytes).expect("failed to deserialize phony public key")
}

fn winternitz_encode(
    parameter: &[KoalaBear; PARAMETER_LEN],
    epoch: u32,
    randomness: &[KoalaBear; RAND_LEN],
    message: &[u8; MESSAGE_LENGTH],
) -> Vec<u8> {
    let mut chunks_message = poseidon_message_hash(parameter, epoch, randomness, message);
    let checksum: u64 = chunks_message
        .iter()
        .map(|&x| BASE_W1 as u64 - 1 - x as u64)
        .sum();

    let mut checksum_chunks = bytes_to_chunks(&checksum.to_le_bytes(), CHUNK_SIZE_W1);
    if checksum_chunks.len() < NUM_CHUNKS_CHECKSUM_W1 {
        checksum_chunks.resize(NUM_CHUNKS_CHECKSUM_W1, 0);
    }
    chunks_message.extend_from_slice(&checksum_chunks[..NUM_CHUNKS_CHECKSUM_W1]);
    chunks_message
}

fn poseidon_message_hash(
    parameter: &[KoalaBear; PARAMETER_LEN],
    epoch: u32,
    randomness: &[KoalaBear; RAND_LEN],
    message: &[u8; MESSAGE_LENGTH],
) -> Vec<u8> {
    let perm = poseidon2_24();
    let message_fe: [KoalaBear; MSG_LEN_FE] = encode_message(message);
    let epoch_fe: [KoalaBear; TWEAK_LEN_FE] = encode_epoch(epoch);

    let mut combined_input =
        Vec::with_capacity(RAND_LEN + PARAMETER_LEN + TWEAK_LEN_FE + MSG_LEN_FE);
    combined_input.extend_from_slice(randomness);
    combined_input.extend_from_slice(parameter);
    combined_input.extend_from_slice(&epoch_fe);
    combined_input.extend_from_slice(&message_fe);

    let hash_fe = poseidon_compress::<_, 24, HASH_LEN_FE>(&perm, &combined_input);
    decode_to_chunks::<NUM_CHUNKS_W1, BASE_W1, HASH_LEN_FE>(&hash_fe).to_vec()
}

fn encode_message<const N: usize>(message: &[u8; MESSAGE_LENGTH]) -> [KoalaBear; N] {
    let mut acc = BigUint::from_bytes_le(message);
    let modulus = BigUint::from(KoalaBear::ORDER_U64);
    std::array::from_fn(|_| {
        let digit = (&acc % &modulus).to_u64().expect("field digit fits in u64");
        acc /= &modulus;
        KoalaBear::from_u32(digit as u32)
    })
}

fn encode_epoch<const N: usize>(epoch: u32) -> [KoalaBear; N] {
    let acc = ((epoch as u64) << 8) | (TWEAK_SEPARATOR_FOR_MESSAGE_HASH as u64);
    let mut result = [KoalaBear::ZERO; N];
    if N > 0 {
        result[0] = KoalaBear::from_u32((acc % KoalaBear::ORDER_U64) as u32);
    }
    if N > 1 {
        result[1] = KoalaBear::from_u32((acc / KoalaBear::ORDER_U64) as u32);
    }
    result
}

fn bytes_to_chunks(bytes: &[u8], chunk_size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mask = (1u32 << chunk_size) - 1;
    for &byte in bytes {
        acc |= (byte as u32) << bits;
        bits += 8;
        while bits >= chunk_size {
            out.push((acc & mask) as u8);
            acc >>= chunk_size;
            bits -= chunk_size;
        }
    }
    if bits > 0 {
        out.push((acc & mask) as u8);
    }
    out
}

fn decode_to_chunks<const DIMENSION: usize, const BASE: usize, const HASH_LEN: usize>(
    field_elements: &[KoalaBear; HASH_LEN],
) -> [u8; DIMENSION] {
    let modulus = BigUint::from(KoalaBear::ORDER_U64);
    let mut acc = BigUint::ZERO;
    for fe in field_elements {
        acc = &acc * &modulus + BigUint::from(fe.as_canonical_u64());
    }
    let base = BigUint::from(BASE as u64);
    std::array::from_fn(|_| {
        let chunk = (&acc % &base).to_u64().expect("chunk fits in u64") as u8;
        acc /= &base;
        chunk
    })
}

fn build_wots_hashes(
    rng: &mut StdRng,
    parameter: &[KoalaBear; PARAMETER_LEN],
    epoch: u32,
    encoding: &[u8],
) -> (Vec<Digest>, Vec<Digest>) {
    let mut hashes = Vec::with_capacity(NUM_CHAINS);
    let mut chain_ends = Vec::with_capacity(NUM_CHAINS);
    for (chain_index, &xi) in encoding.iter().enumerate() {
        let mut value: Digest = rng.random();
        for step in 0..xi {
            value = chain_step(parameter, epoch, chain_index as u8, step, &value);
        }

        let mut end = value;
        for step in xi as usize..CHAIN_LENGTH.saturating_sub(1) {
            end = chain_step(parameter, epoch, chain_index as u8, step as u8, &end);
        }
        hashes.push(value);
        chain_ends.push(end);
    }
    (hashes, chain_ends)
}

fn chain_step(
    parameter: &[KoalaBear; PARAMETER_LEN],
    epoch: u32,
    chain_index: u8,
    position: u8,
    start: &Digest,
) -> Digest {
    let tweak = PoseidonTweak::Chain {
        epoch,
        chain_index,
        pos_in_chain: position + 1,
    };
    poseidon_chain_hash(parameter, &tweak, start)
}

fn poseidon_chain_hash(
    parameter: &[KoalaBear; PARAMETER_LEN],
    tweak: &PoseidonTweak,
    message: &Digest,
) -> Digest {
    let tweak_fe = tweak.to_field_elements::<TWEAK_LEN_FE>();
    let perm = poseidon2_16();
    let mut combined_input = Vec::with_capacity(PARAMETER_LEN + TWEAK_LEN_FE + HASH_LEN_FE);
    combined_input.extend_from_slice(parameter);
    combined_input.extend_from_slice(&tweak_fe);
    combined_input.extend_from_slice(message);
    poseidon_compress::<_, 16, HASH_LEN_FE>(&perm, &combined_input)
}

fn build_merkle_path(
    rng: &mut StdRng,
    parameter: &[KoalaBear; PARAMETER_LEN],
    epoch: u32,
    leaf: &[Digest],
) -> (Vec<Digest>, Digest) {
    let mut co_path = Vec::with_capacity(LOG_LIFETIME);
    let mut current_node = hash_leaf(parameter, epoch, leaf);
    let mut position = epoch;
    for level in 0..LOG_LIFETIME {
        let sibling: Digest = rng.random();
        let is_left = position % 2 == 0;
        let children = if is_left {
            [current_node, sibling]
        } else {
            [sibling, current_node]
        };
        let parent = hash_internal(parameter, level + 1, position >> 1, &children);
        co_path.push(sibling);
        current_node = parent;
        position >>= 1;
    }
    (co_path, current_node)
}

fn hash_leaf(parameter: &[KoalaBear; PARAMETER_LEN], position: u32, leaf: &[Digest]) -> Digest {
    let tweak = PoseidonTweak::Tree {
        level: 0,
        pos_in_level: position,
    };
    poseidon_leaf_hash(parameter, &tweak, leaf)
}

fn hash_internal(
    parameter: &[KoalaBear; PARAMETER_LEN],
    level: usize,
    pos_in_level: u32,
    children: &[Digest],
) -> Digest {
    let tweak = PoseidonTweak::Tree {
        level: level as u8,
        pos_in_level,
    };
    poseidon_leaf_hash(parameter, &tweak, children)
}

fn poseidon_leaf_hash(
    parameter: &[KoalaBear; PARAMETER_LEN],
    tweak: &PoseidonTweak,
    message: &[Digest],
) -> Digest {
    if message.len() > 2 {
        poseidon_sponge_hash(parameter, tweak, message)
    } else {
        let perm = poseidon2_24();
        let tweak_fe = tweak.to_field_elements::<TWEAK_LEN_FE>();
        let mut combined_input =
            Vec::with_capacity(PARAMETER_LEN + TWEAK_LEN_FE + message.len() * HASH_LEN_FE);
        combined_input.extend_from_slice(parameter);
        combined_input.extend_from_slice(&tweak_fe);
        for chunk in message {
            combined_input.extend_from_slice(chunk);
        }
        poseidon_compress::<_, 24, HASH_LEN_FE>(&perm, &combined_input)
    }
}

fn poseidon_sponge_hash(
    parameter: &[KoalaBear; PARAMETER_LEN],
    tweak: &PoseidonTweak,
    message: &[Digest],
) -> Digest {
    let perm = poseidon2_24();
    let capacity_value = {
        let mut v = Vec::with_capacity(PARAMETER_LEN + TWEAK_LEN_FE);
        v.extend_from_slice(parameter);
        v.extend_from_slice(&tweak.to_field_elements::<TWEAK_LEN_FE>());
        v
    };
    let flattened: Vec<KoalaBear> = message.iter().flat_map(|d| d.iter().copied()).collect();
    poseidon_sponge::<_, 24, HASH_LEN_FE>(&perm, &capacity_value, &flattened)
}

fn poseidon_compress<P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    input: &[KoalaBear],
) -> [KoalaBear; OUT_LEN]
where
    P: Permutation<[KoalaBear; WIDTH]>,
{
    assert!(input.len() >= OUT_LEN);

    let mut padded_input = [KoalaBear::ZERO; WIDTH];
    padded_input[..input.len()].copy_from_slice(input);

    let mut state = padded_input;
    perm.permute_mut(&mut state);

    for (state_elem, input_elem) in state.iter_mut().zip(padded_input.iter()) {
        *state_elem += *input_elem;
    }

    state[..OUT_LEN]
        .try_into()
        .expect("output shorter than permutation width")
}

fn poseidon_sponge<P, const WIDTH: usize, const OUT_LEN: usize>(
    perm: &P,
    capacity_value: &[KoalaBear],
    input: &[KoalaBear],
) -> [KoalaBear; OUT_LEN]
where
    P: Permutation<[KoalaBear; WIDTH]>,
{
    assert!(capacity_value.len() < WIDTH);
    let rate = WIDTH - capacity_value.len();

    let extra_elements = (rate - (input.len() % rate)) % rate;
    let mut input_vector = input.to_vec();
    input_vector.extend(std::iter::repeat(KoalaBear::ZERO).take(extra_elements));

    let mut state = [KoalaBear::ZERO; WIDTH];
    state[..capacity_value.len()].copy_from_slice(capacity_value);

    for chunk in input_vector.chunks(rate) {
        for (dst, src) in state[capacity_value.len()..capacity_value.len() + chunk.len()]
            .iter_mut()
            .zip(chunk)
        {
            *dst += *src;
        }
        perm.permute_mut(&mut state);
    }

    state[..OUT_LEN]
        .try_into()
        .expect("output shorter than permutation width")
}

enum PoseidonTweak {
    Tree {
        level: u8,
        pos_in_level: u32,
    },
    Chain {
        epoch: u32,
        chain_index: u8,
        pos_in_chain: u8,
    },
}

impl PoseidonTweak {
    fn to_field_elements<const N: usize>(&self) -> [KoalaBear; N] {
        let mut acc = match self {
            PoseidonTweak::Tree {
                level,
                pos_in_level,
            } => {
                ((*level as u128) << 40)
                    | ((*pos_in_level as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_TREE_HASH as u128)
            }
            PoseidonTweak::Chain {
                epoch,
                chain_index,
                pos_in_chain,
            } => {
                ((*epoch as u128) << 24)
                    | ((*chain_index as u128) << 16)
                    | ((*pos_in_chain as u128) << 8)
                    | (TWEAK_SEPARATOR_FOR_CHAIN_HASH as u128)
            }
        };
        std::array::from_fn(|_| {
            let digit = (acc % KoalaBear::ORDER_U64 as u128) as u64;
            acc /= KoalaBear::ORDER_U64 as u128;
            KoalaBear::from_u32(digit as u32)
        })
    }
}

fn poseidon2_16() -> Poseidon2KoalaBear<16> {
    static INSTANCE: OnceLock<Poseidon2KoalaBear<16>> = OnceLock::new();
    INSTANCE.get_or_init(default_koalabear_poseidon2_16).clone()
}

fn poseidon2_24() -> Poseidon2KoalaBear<24> {
    static INSTANCE: OnceLock<Poseidon2KoalaBear<24>> = OnceLock::new();
    INSTANCE.get_or_init(default_koalabear_poseidon2_24).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_message(tag: u8) -> [u8; MESSAGE_LENGTH] {
        std::array::from_fn(|i| tag.wrapping_add(i as u8))
    }

    #[test]
    fn phony_signature_has_full_path() {
        let item = generate_phony_item(5, test_message(1), 42);
        let raw_sig = serialize_signature(&item.signature);
        assert_eq!(raw_sig.path.co_path.len(), LOG_LIFETIME);
    }

    #[test]
    fn phony_signature_is_deterministic_per_seed() {
        let a = generate_phony_item(10, test_message(2), 999);
        let b = generate_phony_item(10, test_message(2), 999);
        assert_eq!(
            bincode::serialize(&a.signature).unwrap(),
            bincode::serialize(&b.signature).unwrap()
        );
        assert_eq!(
            bincode::serialize(&a.public_key).unwrap(),
            bincode::serialize(&b.public_key).unwrap()
        );
    }
}
