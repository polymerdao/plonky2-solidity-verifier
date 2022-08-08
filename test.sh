cargo test --color=always --package plonky2_solidity_verifier --lib verifier::tests::test_verifier_without_public_inputs
cd contract || exit
npx hardhat test
