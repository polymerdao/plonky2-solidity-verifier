# Solidity verifier for Plonky2

Updates
-----

- **9/11/2022** Added public inputs support. Temporarily use sha256 as the public inputs hash function (slightly more gas than keccak256) due to missing keccak256 plonky2 circuits. Current gas cost of verifying a 60kb proof is around 5m.
- **9/2/2022** Implemented verify_fri_proof(). This project is close to the first milestone and the current gas cost of verifying a 50kb proof is around 4m.

Milestones
-----
This project reaches the first milestone that is to verify a dummy plonky2 proof with public inputs using the following settings:
- High rate config
- GoldilocksField
- QuadraticExtension
- KeccakHash<25> as inner hasher
- Sha256 as the public input hasher

The next milestone is to verify any recursive proof with the above settings.

Things to do for this milestone:

+ [ ] implement all required evaluate_gate_constraints()
+ [ ] gas cost optimization

Optional:

+ [ ] zero knowledge support

Results
-----
Run tests with the following command lines.

```shell
npm install --save-dev hardhat
```

```shell
./test_dummy_proof_with_public_inputs.sh

Generating solidity verifier files ...

successes:
    verifier::tests::test_verifier_with_public_inputs

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 28.40s

Generating typings for: 9 artifacts in dir: typechain-types for target: ethers-v5
Successfully generated 14 typings!
Compiled 9 Solidity files successfully

  Verifier
    Verify
proof size: 59243
      ✓ Should verify the proof

·-----------------------|---------------------------|-------------|-----------------------------·
|  Solc version: 0.8.9  ·  Optimizer enabled: true  ·  Runs: 200  ·  Block limit: 30000000 gas  │
························|···························|·············|······························
|  Methods                                                                                      │
·············|··········|·············|·············|·············|···············|··············
|  Contract  ·  Method  ·  Min        ·  Max        ·  Avg        ·  # calls      ·  usd (avg)  │
·············|··········|·············|·············|·············|···············|··············
|  Deployments          ·                                         ·  % of limit   ·             │
························|·············|·············|·············|···············|··············
|  Plonky2Verifier      ·          -  ·          -  ·    4848087  ·       16.2 %  ·          -  │
·-----------------------|-------------|-------------|-------------|---------------|-------------·

  1 passing (1m)

```

