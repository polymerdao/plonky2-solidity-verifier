use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::config::GenericConfig;

pub fn generate_solidity_verifier<F: RichField + Extendable<D>, C: GenericConfig<D, F=F>, const D: usize>(
    common: CommonCircuitData<F, C, D>,
    verifier_only: VerifierOnlyCircuitData<C, D>) -> (String, Result<()>) {
    println!("Generating solidity verifier files ...");

    // Load template contract
    let mut contract = std::fs::read_to_string("./src/template.sol")
        .expect("Something went wrong reading the file");

    contract = contract.replace("$SIGMA_CAP","0xe1629b9dda060bb30c7908346f6af189c16773fa148d3366701fbaa35d54f3c8");

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

        let mut file = File::create("./contract/contracts/Verifier.sol")?;
        file.write_all(contract.as_bytes())?;
        status
    }
}
