# Solidity verifier for Plonky2

Updates
-----

- **9/28/2022** Current gas cost for verification of a size 50855 dummy proof is 27M.
- **9/27/2022** Added more gates support. Updated gas estimations.
- **9/11/2022** Added public inputs support. Temporarily use sha256 as the public inputs hash function (slightly more
  gas than keccak256) due to missing keccak256 plonky2 circuits.
- **9/2/2022** Implemented verify_fri_proof().

Milestones
-----
This project reaches the first milestone that is to verify a dummy plonky2 proof with public inputs using the following
settings:

- High rate config
- GoldilocksField
- QuadraticExtension
- KeccakHash<25> as inner hasher
- Sha256 as the public input hasher

The next milestone is to verify any recursive proof with the above settings.

Things to do for this milestone:

Implement all required gate constraints evaluation and gas cost optimization:

+ [x] NoopGate
+ [x] ConstantGate
+ [x] PublicInputGate
+ [x] BaseSumGate
+ [x] LowDegreeInterpolationGate
+ [x] ReducingExtensionGate
+ [x] ReducingGate
+ [x] ArithmeticGate
+ [x] U32ArithmeticGate
+ [x] ArithmeticExtensionGate
+ [x] MulExtensionGate
+ [x] ExponentiationGate
+ [x] RandomAccessGate
+ [ ] PoseidonGate

Optional:

+ [ ] Zero knowledge support

Results
-----
Run tests with the following command lines.

```shell
npm install --save-dev hardhat
```

```shell
./test_dummy_proof_without_public_inputs.sh

Generating solidity verifier files ...

successes:
    verifier::tests::test_verifier_without_public_inputs

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; finished in 3.62s

Generating typings for: 12 artifacts in dir: typechain-types for target: ethers-v5
Successfully generated 14 typings!
Compiled 10 Solidity files successfully

  Verifier
    Verify
proof size: 50855
      ✓ Should verify the proof

·--------------------------------------|---------------------------|-------------|-------------------------------·
|         Solc version: 0.8.9          ·  Optimizer enabled: true  ·  Runs: 200  ·  Block limit: 3000000000 gas  │
·······································|···························|·············|································
|  Methods                                                                                                       │
····················|··················|·············|·············|·············|················|···············
|  Contract         ·  Method          ·  Min        ·  Max        ·  Avg        ·  # calls       ·  usd (avg)   │
····················|··················|·············|·············|·············|················|···············
|  Plonky2Verifier  ·  execute_verify  ·          -  ·          -  ·   27199014  ·             1  ·           -  │
····················|··················|·············|·············|·············|················|···············
|  Deployments                         ·                                         ·  % of limit    ·              │
·······································|·············|·············|·············|················|···············
|  Plonky2Verifier                     ·          -  ·          -  ·    3818777  ·         0.1 %  ·           -  │
·--------------------------------------|-------------|-------------|-------------|----------------|--------------·

  1 passing (12s)

```
