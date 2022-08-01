use anyhow::Result;

pub fn export_solidity_verifier() -> Result<()> {
    println!("Generating solidity verifier files ...");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::verifier::export_solidity_verifier;
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

    #[test]
    fn test_verifier_without_public_inputs() -> Result<()> {
        let config = CircuitConfig::standard_recursion_config();

        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let num_dummy_gates = 1000;
        info!("Constructing proof with {} gates", num_dummy_gates);
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        for _ in 0..num_dummy_gates {
            builder.add_gate(NoopGate, vec![]);
        }
        builder.print_gate_counts(0);

        let data = builder.build::<C>();
        let inputs = PartialWitness::new();

        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(&data.prover_only, &data.common, inputs, &mut timing)?;
        timing.print();
        data.verify(proof.clone())?;

        export_solidity_verifier()
    }
}
