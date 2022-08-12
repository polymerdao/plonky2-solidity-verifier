use anyhow::Result;
use log::Level;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::config::GenericHashOut;
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

pub struct VerifierConfig {
    num_wires_cap: usize,
    num_plonk_zs_partial_products_cap: usize,
    num_quotient_polys_cap: usize,

    // openings
    num_openings_constants: usize,
    num_openings_plonk_sigmas: usize,
    num_openings_wires: usize,
    num_openings_plonk_zs: usize,
    num_openings_plonk_zs_next: usize,
    num_openings_partial_products: usize,
    num_openings_quotient_polys: usize,

    // fri proof
    // .commit phase
    num_fri_commit_round: usize,
    fri_commit_merkle_cap_height: usize,
    // .query round
    num_fri_query_round: usize,
    // ..init
    num_fri_query_init_constants_sigmas_v: usize,
    num_fri_query_init_constants_sigmas_p: usize,
    num_fri_query_init_wires_v: usize,
    num_fri_query_init_wires_p: usize,
    num_fri_query_init_zs_partial_v: usize,
    num_fri_query_init_zs_partial_p: usize,
    num_fri_query_init_quotient_v: usize,
    num_fri_query_init_quotient_p: usize,
    // ..steps
    num_fri_query_step0_v: usize,
    num_fri_query_step0_p: usize,
    num_fri_query_step1_v: usize,
    num_fri_query_step1_p: usize,
    // .final poly
    num_fri_final_poly_ext_v: usize,
    // public inputs
}

// TODO: The input should be CommonCircuitData
pub fn generate_verifier_config<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    pwpi: &ProofWithPublicInputs<F, C, D>,
) -> anyhow::Result<VerifierConfig> {
    let proof = &pwpi.proof;
    assert_eq!(proof.opening_proof.query_round_proofs[0].steps.len(), 2);
    let conf = VerifierConfig {
        num_wires_cap: proof.wires_cap.0.len(),
        num_plonk_zs_partial_products_cap: proof.plonk_zs_partial_products_cap.0.len(),
        num_quotient_polys_cap: proof.quotient_polys_cap.0.len(),

        num_openings_constants: proof.openings.constants.len(),
        num_openings_plonk_sigmas: proof.openings.plonk_sigmas.len(),
        num_openings_wires: proof.openings.wires.len(),
        num_openings_plonk_zs: proof.openings.plonk_zs.len(),
        num_openings_plonk_zs_next: proof.openings.plonk_zs_next.len(),
        num_openings_partial_products: proof.openings.partial_products.len(),
        num_openings_quotient_polys: proof.openings.quotient_polys.len(),

        num_fri_commit_round: proof.opening_proof.commit_phase_merkle_caps.len(),
        fri_commit_merkle_cap_height: proof.opening_proof.commit_phase_merkle_caps[0].0.len(),
        num_fri_query_round: proof.opening_proof.query_round_proofs.len(),
        num_fri_query_init_constants_sigmas_v: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .0
            .len(),
        num_fri_query_init_constants_sigmas_p: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1
            .siblings
            .len(),
        num_fri_query_init_wires_v: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[1]
            .0
            .len(),
        num_fri_query_init_wires_p: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[1]
            .1
            .siblings
            .len(),
        num_fri_query_init_zs_partial_v: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[2]
            .0
            .len(),
        num_fri_query_init_zs_partial_p: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[2]
            .1
            .siblings
            .len(),
        num_fri_query_init_quotient_v: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[3]
            .0
            .len(),
        num_fri_query_init_quotient_p: proof.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[3]
            .1
            .siblings
            .len(),
        num_fri_query_step0_v: proof.opening_proof.query_round_proofs[0].steps[0]
            .evals
            .len(),
        num_fri_query_step0_p: proof.opening_proof.query_round_proofs[0].steps[0]
            .merkle_proof
            .siblings
            .len(),
        num_fri_query_step1_v: proof.opening_proof.query_round_proofs[0].steps[1]
            .evals
            .len(),
        num_fri_query_step1_p: proof.opening_proof.query_round_proofs[0].steps[1]
            .merkle_proof
            .siblings
            .len(),
        num_fri_final_poly_ext_v: proof.opening_proof.final_poly.coeffs.len(),
    };
    Ok(conf)
}

pub fn generate_proof_base64<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    pwpi: &ProofWithPublicInputs<F, C, D>,
    conf: &VerifierConfig,
) -> anyhow::Result<String> {
    assert_eq!(pwpi.public_inputs.len(), 0);

    const HASH_SIZE: usize = 25;
    const FIELD_SIZE: usize = 8;
    const EXT_FIELD_SIZE: usize = 16;
    const MERKLE_LENGTH: usize = 1;

    // 75
    let mut proof_size: usize =
        (conf.num_wires_cap + conf.num_plonk_zs_partial_products_cap + conf.num_quotient_polys_cap)
            * HASH_SIZE;

    // 3355
    proof_size += (conf.num_openings_constants
        + conf.num_openings_plonk_sigmas
        + conf.num_openings_wires
        + conf.num_openings_plonk_zs
        + conf.num_openings_plonk_zs_next
        + conf.num_openings_partial_products
        + conf.num_openings_quotient_polys)
        * EXT_FIELD_SIZE;

    // 3405
    proof_size += (conf.num_fri_commit_round * conf.fri_commit_merkle_cap_height) * HASH_SIZE;
    // 39685
    proof_size += conf.num_fri_query_round
        * ((conf.num_fri_query_init_constants_sigmas_v
            + conf.num_fri_query_init_wires_v
            + conf.num_fri_query_init_zs_partial_v
            + conf.num_fri_query_init_quotient_v)
            * FIELD_SIZE
            + (conf.num_fri_query_init_constants_sigmas_p
                + conf.num_fri_query_init_wires_p
                + conf.num_fri_query_init_zs_partial_p
                + conf.num_fri_query_init_quotient_p)
                * HASH_SIZE
            + MERKLE_LENGTH * 4);
    // 50015
    proof_size += conf.num_fri_query_round
        * (conf.num_fri_query_step0_v * EXT_FIELD_SIZE
            + conf.num_fri_query_step0_p * HASH_SIZE
            + MERKLE_LENGTH
            + conf.num_fri_query_step1_v * EXT_FIELD_SIZE
            + conf.num_fri_query_step1_p * HASH_SIZE
            + MERKLE_LENGTH);

    // 51039
    proof_size += conf.num_fri_final_poly_ext_v * EXT_FIELD_SIZE;

    // 51047
    proof_size += FIELD_SIZE;

    let proof_bytes = pwpi.to_bytes()?;
    assert_eq!(proof_bytes.len(), proof_size);

    Ok(base64::encode(proof_bytes))
}

pub fn generate_solidity_verifier<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    common: &CommonCircuitData<F, C, D>,
    verifier_only: &VerifierOnlyCircuitData<C, D>,
) -> anyhow::Result<String> {
    assert_eq!(
        25,
        C::Hasher::HASH_SIZE,
        "Only support KeccakHash<25> right now"
    );
    assert_eq!(F::BITS, 64);
    assert_eq!(F::Extension::BITS, 128);
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

    Ok(contract)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use anyhow::Result;
    use log::{info, Level};
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
    use plonky2::fri::FriConfig;
    use plonky2::fri::reduction_strategies::FriReductionStrategy;
    use plonky2::plonk::config::KeccakGoldilocksConfig;

    use crate::verifier::{
        generate_proof_base64, generate_solidity_verifier, generate_verifier_config,
        recursive_proof,
        };

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

        let contract = generate_solidity_verifier(&cd, &vd)?;

        let mut sol_file = File::create("./contract/contracts/Verifier.sol")?;
        sol_file.write_all(contract.as_bytes())?;

        let conf = generate_verifier_config(&proof)?;
        let proof_base64 = generate_proof_base64(&proof, &conf)?;
        let proof_json = "[ \"".to_owned() + &proof_base64 + &"\" ]";

        if !Path::new("./contract/test/data").is_dir() {
            std::fs::create_dir("./contract/test/data")?;
        }

        let mut proof_file = File::create("./contract/test/data/proof.json")?;
        proof_file.write_all(proof_json.as_bytes())?;

        Ok(())
    }
}
