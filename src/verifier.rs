use anyhow::Result;
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::GenericHashOut;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;

fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner_proof: ProofWithPublicInputs<F, InnerC, D>,
    inner_vd: VerifierOnlyCircuitData<InnerC, D>,
    inner_cd: CommonCircuitData<F, InnerC, D>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
    print_gate_counts: bool,
    print_timing: bool,
) -> Result<(
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, C, D>,
)>
where
    InnerC::Hasher: AlgebraicHasher<F>,
    [(); C::Hasher::HASH_SIZE]:,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();
    let pt = builder.add_virtual_proof_with_pis(&inner_cd);
    pw.set_proof_with_pis_target(&pt, &inner_proof);

    let inner_data = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
    };
    pw.set_cap_target(
        &inner_data.constants_sigmas_cap,
        &inner_vd.constants_sigmas_cap,
    );

    builder.verify_proof(pt, &inner_data, &inner_cd);

    if print_gate_counts {
        builder.print_gate_counts(0);
    }

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will add a
        // few special gates afterward. So just pad to 2^(min_degree_bits - 1) + 1. Then the
        // builder will pad to the next power of two, 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    if print_timing {
        timing.print();
    }

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn generate_solidity_verifier<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    common: CommonCircuitData<F, C, D>,
    verifier_only: VerifierOnlyCircuitData<C, D>,
) -> (String, Result<()>) {
    println!("Generating solidity verifier files ...");

    // Load template contract
    let mut contract = std::fs::read_to_string("./src/template.sol")
        .expect("Something went wrong reading the file");

    let sigma_cap_count = 1 << common.config.fri_config.cap_height;
    contract = contract.replace("$SIGMA_CAP_COUNT", &*sigma_cap_count.to_string());

    let mut sigma_cap_str = "".to_owned();
    for i in 0..sigma_cap_count {
        let cap = verifier_only.constants_sigmas_cap.0[i];
        let hash_vec = cap.to_bytes();
        let mut hash = "".to_owned();
        for b in &hash_vec {
            hash += &format!("{:#04x}", b)[2..4];
        }
        sigma_cap_str += &*("        sc[".to_owned() + &*i.to_string() + "] = 0x" + &*hash + ";\n");
    }
    contract = contract.replace("        $SET_SIGMA_CAP;\n", &*sigma_cap_str);

    (contract, Ok(()))
}

#[cfg(test)]
mod tests {
    use crate::verifier::{generate_solidity_verifier, recursive_proof};
    use anyhow::Result;
    use log::{info, Level};
    use plonky2::fri::reduction_strategies::FriReductionStrategy;
    use plonky2::fri::FriConfig;
    use plonky2::plonk::config::KeccakGoldilocksConfig;
    use plonky2::{
        gates::noop::NoopGate,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
            prover::prove,
        },
        util::timing::TimingTree,
    };
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn test_verifier_without_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type KC = KeccakGoldilocksConfig;
        let standard_config = CircuitConfig::standard_recursion_config();

        const NUM_DUMMY_GATES: usize = 4000;
        info!("Constructing proof with {} gates", NUM_DUMMY_GATES);
        let mut builder = CircuitBuilder::<F, D>::new(standard_config.clone());
        for _ in 0..NUM_DUMMY_GATES {
            builder.add_gate(NoopGate, vec![]);
        }
        builder.print_gate_counts(0);

        let data = builder.build::<C>();
        let inputs = PartialWitness::new();

        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(&data.prover_only, &data.common, inputs, &mut timing)?;
        timing.print();
        data.verify(proof.clone())?;
        let vd = data.verifier_only;
        let cd = data.common;

        // A high-rate recursive proof, designed to be verifiable with fewer routed wires.
        let high_rate_config = CircuitConfig {
            fri_config: FriConfig {
                rate_bits: 7,
                proof_of_work_bits: 16,
                num_query_rounds: 12,
                ..standard_config.fri_config.clone()
            },
            ..standard_config
        };

        // A final proof, optimized for size.
        let final_config = CircuitConfig {
            num_routed_wires: 37,
            fri_config: FriConfig {
                rate_bits: 8,
                cap_height: 0,
                proof_of_work_bits: 20,
                reduction_strategy: FriReductionStrategy::MinSize(None),
                num_query_rounds: 10,
            },
            ..high_rate_config
        };
        let (proof, vd, cd) =
            recursive_proof::<F, KC, C, D>(proof, vd, cd, &final_config, None, true, true)?;

        let (contract, status) = generate_solidity_verifier(cd, vd);

        let mut sol_file = File::create("./contract/contracts/Verifier.sol")?;
        sol_file.write_all(contract.as_bytes())?;

        let proof_bytes = proof.to_bytes()?;
        println!("proof size: {}", proof_bytes.len());
        let proof_base64 = base64::encode(proof_bytes);
        let proof_json = "[ \"".to_owned() + &proof_base64 + &"\" ]";

        if !Path::new("./contract/test/data").is_dir() {
            std::fs::create_dir("./contract/test/data")?;
        }

        let mut proof_file = File::create("./contract/test/data/proof.json")?;
        proof_file.write_all(proof_json.as_bytes())?;
        status
    }
}
