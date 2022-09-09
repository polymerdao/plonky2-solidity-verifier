use std::iter;
use std::mem::size_of;

use itertools::Itertools;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{BytesHash, HashOut, HashOutTarget, RichField};
use plonky2::hash::hashing::{PlonkyPermutation, SPONGE_WIDTH};
use plonky2::hash::keccak::{KeccakHash, KeccakPermutation};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut, Hasher};
use plonky2::util::serialization::Buffer;
use plonky2_sha256::split_base::CircuitBuilderSplit;
use sha2::{Digest, Sha256};

pub fn sha256<T: AsRef<[u8]>>(s: T) -> keccak_hash::H256 {
    let mut hasher = Sha256::new();
    hasher.update(s);
    keccak_hash::H256(<[u8; 32]>::try_from(hasher.finalize().as_slice()).unwrap())
}

pub struct Sha256Permutation;

impl<F: RichField> PlonkyPermutation<F> for Sha256Permutation {
    fn permute(input: [F; SPONGE_WIDTH]) -> [F; SPONGE_WIDTH] {
        let mut state = vec![0u8; SPONGE_WIDTH * size_of::<u64>()];
        for i in 0..SPONGE_WIDTH {
            state[i * size_of::<u64>()..(i + 1) * size_of::<u64>()]
                .copy_from_slice(&input[i].to_canonical_u64().to_le_bytes());
        }

        let hash_onion = iter::repeat_with(|| {
            let output = sha256(state.clone()).to_fixed_bytes();
            state = output.to_vec();
            output
        });

        let hash_onion_u64s = hash_onion.flat_map(|output| {
            output
                .chunks_exact(size_of::<u64>())
                .map(|word| u64::from_le_bytes(word.try_into().unwrap()))
                .collect_vec()
        });

        // Parse field elements from u64 stream, using rejection sampling such that words that don't
        // fit in F are ignored.
        let hash_onion_elems = hash_onion_u64s
            .filter(|&word| word < F::ORDER)
            .map(F::from_canonical_u64);

        hash_onion_elems
            .take(SPONGE_WIDTH)
            .collect_vec()
            .try_into()
            .unwrap()
    }
}

/// Sha-256 hash function.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Sha256Hash<const N: usize>;

impl<F: RichField, const N: usize> Hasher<F> for Sha256Hash<N> {
    const HASH_SIZE: usize = N;
    type Hash = BytesHash<N>;
    type Permutation = Sha256Permutation;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        let mut buffer = Buffer::new(Vec::new());
        buffer.write_field_vec(input).unwrap();
        let mut arr = [0; N];
        let hash_bytes = sha256(buffer.bytes()).0;
        arr.copy_from_slice(&hash_bytes[..N]);
        BytesHash(arr)
    }

    fn hash_public_inputs(input: &[F]) -> Self::Hash {
        Sha256Hash::hash_no_pad(input)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let mut v = vec![0; N * 2];
        v[0..N].copy_from_slice(&left.0);
        v[N..].copy_from_slice(&right.0);
        let mut arr = [0; N];
        arr.copy_from_slice(&sha256(v).0[..N]);
        BytesHash(arr)
    }
}

/// Sha-256 hash function.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AlgebraicSha256Hash;

impl<F: RichField> Hasher<F> for AlgebraicSha256Hash {
    const HASH_SIZE: usize = 32;
    type Hash = HashOut<F>;
    type Permutation = Sha256Permutation;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        if input.len() == 0 {
            return HashOut::from_vec([F::ZERO, F::ZERO, F::ZERO, F::ZERO].to_vec());
        }
        let bytes_hash = Sha256Hash::<32>::hash_no_pad(input);
        HashOut::from_bytes(&bytes_hash.0)
    }

    fn hash_public_inputs(input: &[F]) -> Self::Hash {
        AlgebraicSha256Hash::hash_no_pad(input)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let input = [left.elements, right.elements].concat();
        AlgebraicSha256Hash::hash_no_pad(&input)
    }
}

// TODO: This is a workaround and only used in public inputs hash.
impl<F: RichField> AlgebraicHasher<F> for AlgebraicSha256Hash {
    fn permute_swapped<const D: usize>(
        _: [Target; SPONGE_WIDTH],
        _: BoolTarget,
        _: &mut CircuitBuilder<F, D>,
    ) -> [Target; SPONGE_WIDTH]
    where
        F: RichField + Extendable<D>,
    {
        todo!("implement it")
    }
    fn public_inputs_hash<const D: usize>(
        inputs: Vec<Target>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget
    where
        F: RichField + Extendable<D>,
    {
        let msg_len_in_bits = (inputs.len() * 64) as u64;
        if msg_len_in_bits == 0u64 {
            return HashOutTarget::from_vec(Vec::from([
                builder.zero(),
                builder.zero(),
                builder.zero(),
                builder.zero(),
            ]));
        }
        let sha256_targets = plonky2_sha256::circuit::make_circuits(builder, msg_len_in_bits);
        for i in 0..inputs.len() {
            let bit_targets = builder.split_le_base::<2>(inputs[i], 64);
            for j in 0..8 {
                for k in 0..8 {
                    builder.connect(
                        sha256_targets.message[i * 64 + j * 8 + k].target,
                        bit_targets[j * 8 + 7 - k],
                    );
                }
            }
        }

        let mut out_targets = Vec::new();
        for i in 0..4 {
            let mut bits = Vec::new();
            for j in 0..8 {
                for k in 0..8 {
                    bits.push(sha256_targets.digest[i * 64 + j * 8 + 7 - k]);
                }
            }
            out_targets.push(builder.le_sum(bits.iter()));
        }
        HashOutTarget::from_vec(out_targets)
    }
}

/// Keccak-256 hash function.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AlgebraicKeccakHash;

impl<F: RichField> Hasher<F> for AlgebraicKeccakHash {
    const HASH_SIZE: usize = 32;
    type Hash = HashOut<F>;
    type Permutation = KeccakPermutation;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        if input.len() == 0 {
            return HashOut::from_vec([F::ZERO, F::ZERO, F::ZERO, F::ZERO].to_vec());
        }
        let bytes_hash = KeccakHash::<32>::hash_no_pad(input);
        HashOut::from_bytes(&bytes_hash.0)
    }

    fn hash_public_inputs(input: &[F]) -> Self::Hash {
        AlgebraicSha256Hash::hash_public_inputs(input)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let input = [left.elements, right.elements].concat();
        AlgebraicKeccakHash::hash_no_pad(&input)
    }
}

// This is a workaround, since it will not be used in this lib.
impl<F: RichField> AlgebraicHasher<F> for AlgebraicKeccakHash {
    fn permute_swapped<const D: usize>(
        _: [Target; SPONGE_WIDTH],
        _: BoolTarget,
        _: &mut CircuitBuilder<F, D>,
    ) -> [Target; SPONGE_WIDTH]
    where
        F: RichField + Extendable<D>,
    {
        todo!("implement it")
    }

    fn public_inputs_hash<const D: usize>(
        inputs: Vec<Target>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget
    where
        F: RichField + Extendable<D>,
    {
        AlgebraicSha256Hash::public_inputs_hash(inputs, builder)
    }
}

/// Configuration using truncated Keccak over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KeccakGoldilocksConfig2;

impl GenericConfig<2> for KeccakGoldilocksConfig2 {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = KeccakHash<25>;
    type InnerHasher = AlgebraicKeccakHash;
}

/// Configuration using truncated Keccak over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Sha256GoldilocksConfig;

impl GenericConfig<2> for Sha256GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = Sha256Hash<25>;
    type InnerHasher = AlgebraicSha256Hash;
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{
        AlgebraicHasher, GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig,
    };
    use plonky2::util::serialization::Buffer;
    use plonky2_sha256::circuit::{array_to_bits, make_circuits};

    use crate::config::{AlgebraicKeccakHash, AlgebraicSha256Hash};

    #[test]
    fn test_algebraic_keccak() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut v = Vec::new();
        v.push(F::from_canonical_u64(8917524657281059100u64));
        v.push(F::from_canonical_u64(13029010200779371910u64));
        v.push(F::from_canonical_u64(16138660518493481604u64));
        v.push(F::from_canonical_u64(17277322750214136960u64));
        v.push(F::from_canonical_u64(1441151880423231822u64));
        let h = AlgebraicKeccakHash::hash_no_pad(&v);
        assert_eq!(h.elements[0].0, 5457815305841349545u64);
        assert_eq!(h.elements[1].0, 8842690375664641093u64);
        assert_eq!(h.elements[2].0, 1933753955848180559u64);
        assert_eq!(h.elements[3].0, 13467638159094989556u64);

        Ok(())
    }

    #[test]
    fn test_sha256_hash() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let f = [
            F::from_canonical_u64(8917524657281059100u64),
            F::from_canonical_u64(13029010200779371910u64),
            F::from_canonical_u64(16138660518493481604u64),
            F::from_canonical_u64(17277322750214136960u64),
            F::from_canonical_u64(1441151880423231822u64),
        ];
        let h = AlgebraicSha256Hash::hash_no_pad(&f);

        let mut msg = Buffer::new(Vec::new());
        msg.write_field_vec(&f).unwrap();

        let len = msg.len() * 8;
        let msg_bits = array_to_bits(&*msg.bytes());

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = make_circuits(&mut builder, len as u64);
        let mut pw = PartialWitness::new();

        for i in 0..len {
            pw.set_bool_target(targets.message[i], msg_bits[i]);
        }

        let expected_res = array_to_bits(&*h.to_bytes());
        for i in 0..expected_res.len() {
            if expected_res[i] {
                builder.assert_one(targets.digest[i].target);
            } else {
                builder.assert_zero(targets.digest[i].target);
            }
        }

        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }

    #[test]
    fn test_public_inputs_hash_sha256() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let f = [
            F::from_canonical_u64(8917524657281059100u64),
            F::from_canonical_u64(13029010200779371910u64),
            F::from_canonical_u64(16138660518493481604u64),
            F::from_canonical_u64(17277322750214136960u64),
            F::from_canonical_u64(1441151880423231822u64),
        ];
        let h = AlgebraicSha256Hash::hash_no_pad(&f);

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let f_targets = builder.constants(f.as_ref());
        let out = AlgebraicSha256Hash::public_inputs_hash(f_targets, &mut builder);

        let h0 = builder.constant(h.elements[0]);
        let h1 = builder.constant(h.elements[1]);
        let h2 = builder.constant(h.elements[2]);
        let h3 = builder.constant(h.elements[3]);
        builder.connect(out.elements[0], h0);
        builder.connect(out.elements[1], h1);
        builder.connect(out.elements[2], h2);
        builder.connect(out.elements[3], h3);

        let pw = PartialWitness::new();
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        data.verify(proof)
    }
}
