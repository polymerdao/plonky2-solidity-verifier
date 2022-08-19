use keccak_hash::keccak;
use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::hashing::SPONGE_WIDTH;
use plonky2::hash::keccak::{KeccakHash, KeccakPermutation};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};

/// Configuration using truncated Keccak over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct KeccakGoldilocksConfig2;

impl GenericConfig<2> for KeccakGoldilocksConfig2 {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = KeccakHash<25>;
    type InnerHasher = AlgebraicKeccakHash;
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
        let size_of_f = F::BITS / 8;
        let mut state = vec![0u8; input.len() * size_of_f];
        for i in 0..input.len() {
            state[i * size_of_f..(i + 1) * size_of_f]
                .copy_from_slice(&input[i].to_canonical_u64().to_le_bytes());
        }

        let h = keccak(state).to_fixed_bytes();
        let mut outputs = Vec::new();

        for i in 0..4 {
            let mut n =
                u64::from_le_bytes(h[i * size_of_f..(i + 1) * size_of_f].try_into().unwrap());
            if n >= F::ORDER {
                n = n - F::ORDER;
            }
            outputs.push(F::from_canonical_u64(n));
        }

        HashOut::from_vec(outputs)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let input = [left.elements, right.elements].concat();
        AlgebraicKeccakHash::hash_no_pad(&input)
    }
}

// This is a workaround, since it will not be used in this lib.
// TODO: implement it.
impl<F: RichField> AlgebraicHasher<F> for AlgebraicKeccakHash {
    fn permute_swapped<const D: usize>(
        _: [Target; SPONGE_WIDTH],
        _: BoolTarget,
        builder: &mut CircuitBuilder<F, D>,
    ) -> [Target; SPONGE_WIDTH]
    where
        F: RichField + Extendable<D>,
    {
        let mut ans = Vec::new();

        for _ in 0..SPONGE_WIDTH {
            ans.push(builder.add_virtual_target());
        }

        <[Target; 12]>::try_from(ans).unwrap()
    }
}
