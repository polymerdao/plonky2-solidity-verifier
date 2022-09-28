// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksField.sol";
import "./GoldilocksExt.sol";

// TODO: more unit tests needed for corner cases.
contract TestGoldilocks {
    function test_add() external {
        require(GoldilocksFieldLib.add(14992246389055333107, 13533945482899040792) == 10079447802539789578);
    }

    function test_mul() external {
        require(GoldilocksFieldLib.mul(16424245004931000714, 2251799813160960) == 5496890231018735829);
    }

    function test_inverse() external {
        require(GoldilocksFieldLib.inverse(6784275835416866020) == 7154952498519749264);
    }

    function test_mul_ext() external {
        uint64[2] memory a;
        a[0] = 4994088319481652598;
        a[1] = 16489566008211790727;
        uint64[2] memory b;
        b[0] = 3797605683985595697;
        b[1] = 13424401189265534004;
        uint64[2] memory res = GoldilocksExtLib.mul(a, b);
        require(res[0] == 15052319864161058789);
        require(res[1] == 16841416332519902625);
    }

    function test_div_ext() external {
        uint64[2] memory a;
        a[0] = 4994088319481652598;
        a[1] = 16489566008211790727;
        uint64[2] memory b;
        b[0] = 7166004739148609569;
        b[1] = 14655965871663555016;
        uint64[2] memory res = GoldilocksExtLib.div(a, b);
        require(res[0] == 15052319864161058789);
        require(res[1] == 16841416332519902625);
    }

    function test_inverse_2exp_12() external {
        require(GoldilocksFieldLib.inverse_2exp(12) == 18442240469788262401);
    }

    function test_inverse_2exp_109() external {
        require(GoldilocksFieldLib.inverse_2exp(109) == 2251799813160960);
    }

    function test_exp() external {
        require(GoldilocksFieldLib.exp(3511170319078647661, 602096) == 8162053712235223550);
    }

    function test_exp_ext() external {
        uint64[2] memory x;
        x[0] = 9076502759914437505;
        x[1] = 16396680756479675411;
        uint64[2] memory res = GoldilocksExtLib.exp(x, 4096);
        require(res[0] == 4994088319481652599);
        require(res[1] == 16489566008211790727);
    }

    function test_repeated_frobenius() external {
        uint64[2] memory x;
        x[0] = 7166004739148609569;
        x[1] = 14655965871663555016;
        uint64[2] memory res = GoldilocksExtLib.repeated_frobenius(x, 1);
        require(res[0] == 7166004739148609569);
        require(res[1] == 3790778197751029305);
    }
}
