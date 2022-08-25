// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksField.sol";
import "./GoldilocksExt.sol";

// TODO: more unit tests needed
contract TestGoldilocks {
    function test_mul() public pure returns (uint64) {
        return GoldilocksFieldLib.mul(16424245004931000714, 2251799813160960);
    }

    function test_inverse_2exp_12() public pure returns (uint64) {
        return GoldilocksFieldLib.inverse_2exp(12);
    }

    function test_inverse_2exp_109() public pure returns (uint64) {
        return GoldilocksFieldLib.inverse_2exp(109);
    }
}
