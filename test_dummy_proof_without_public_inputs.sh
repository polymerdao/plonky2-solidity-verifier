cargo test -r --color=always --package plonky2_solidity_verifier --lib verifier::tests::test_verifier_without_public_inputs --no-fail-fast -- -Z unstable-options --show-output
cd contract || exit
npx hardhat compile
npx hardhat test --grep Verify
