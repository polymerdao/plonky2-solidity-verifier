cargo test --color=always --package plonky2_solidity_verifier --lib verifier --no-fail-fast -- -Z unstable-options --show-output
cd contract || exit
npx hardhat compile
npx hardhat test
