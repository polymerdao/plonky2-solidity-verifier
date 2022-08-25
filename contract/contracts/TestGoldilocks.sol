// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksField.sol";
import "./GoldilocksExt.sol";

// TODO: more unit tests needed for corner cases.
contract TestGoldilocks {
    function test_mul() public pure returns (uint64) {
        return GoldilocksFieldLib.mul(16424245004931000714, 2251799813160960);
    }

    function test_inverse() public pure returns (uint64) {
        return GoldilocksFieldLib.inverse(6784275835416866020);
    }

    function test_mul_ext() public pure returns (uint64[2] memory) {
        uint64[2] memory a;
        a[0] = 4994088319481652598;
        a[1] = 16489566008211790727;
        uint64[2] memory b;
        b[0] = 3797605683985595697;
        b[1] = 13424401189265534004;
        return GoldilocksExtLib.mul(a, b);
    }

    function test_div_ext() public pure returns (uint64[2] memory) {
        uint64[2] memory a;
        a[0] = 4994088319481652598;
        a[1] = 16489566008211790727;
        uint64[2] memory b;
        b[0] = 7166004739148609569;
        b[1] = 14655965871663555016;
        return GoldilocksExtLib.div(a, b);
    }

    function test_inverse_2exp_12() public pure returns (uint64) {
        return GoldilocksFieldLib.inverse_2exp(12);
    }

    function test_inverse_2exp_109() public pure returns (uint64) {
        return GoldilocksFieldLib.inverse_2exp(109);
    }

    function test_exp_ext() public pure returns (uint64[2] memory) {
        uint64[2] memory x;
        x[0] = 9076502759914437505;
        x[1] = 16396680756479675411;
        return GoldilocksExtLib.exp(x, 4096);
    }

    function test_u160_times_7() public pure returns (uint128, uint32) {
        uint64 a1 = 16489566008211790727;
        uint64 b1 = 13424401189265534004;
        uint128 a1_mul_b1 = uint128(a1) * uint128(b1);
        return GoldilocksExtLib.u160_times_7(a1_mul_b1, 0);
    }

    function test_repeated_frobenius() public pure returns (uint64[2] memory) {
        uint64[2] memory x;
        x[0] = 7166004739148609569;
        x[1] = 14655965871663555016;
        return GoldilocksExtLib.repeated_frobenius(x, 1);
    }
}
