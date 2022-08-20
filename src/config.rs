use plonky2::field::extension::quadratic::QuadraticExtension;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::hashing::SPONGE_WIDTH;
use plonky2::hash::keccak::{KeccakHash, KeccakPermutation};
use plonky2::iop::challenger::Challenger;
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
        let mut challenger = Challenger::<F, KeccakHash<32>>::new();
        challenger.observe_elements(input);
        HashOut::from_vec(
            [
                challenger.get_challenge(),
                challenger.get_challenge(),
                challenger.get_challenge(),
                challenger.get_challenge(),
            ]
            .to_vec(),
        )
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
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};

    use crate::config::AlgebraicKeccakHash;

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
        assert_eq!(h.elements[0].0, 10556094283316u64);
        assert_eq!(h.elements[1].0, 2969885698010629776u64);
        assert_eq!(h.elements[2].0, 891839585018115537u64);
        assert_eq!(h.elements[3].0, 6951606774775366384u64);

        Ok(())
    }
}
