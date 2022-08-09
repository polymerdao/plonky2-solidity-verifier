use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::config::GenericHashOut;

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
    use crate::verifier::generate_solidity_verifier;
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
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    #[test]
    fn test_verifier_without_public_inputs() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();

        const NUM_DUMMY_GATES: usize = 1000;
        info!("Constructing proof with {} gates", NUM_DUMMY_GATES);
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
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

        let (contract, status) = generate_solidity_verifier(data.common, data.verifier_only);

        let mut sol_file = File::create("./contract/contracts/Verifier.sol")?;
        sol_file.write_all(contract.as_bytes())?;

        let proof_base64 = base64::encode(proof.to_bytes()?);
        let proof_json = "[ \"".to_owned() + &proof_base64 + &"\" ]";

        if !Path::new("./contract/test/data").is_dir() {
            std::fs::create_dir("./contract/test/data")?;
        }

        let mut proof_file = File::create("./contract/test/data/proof.json")?;
        proof_file.write_all(proof_json.as_bytes())?;
        status
    }
}
