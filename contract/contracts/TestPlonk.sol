// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./Plonk.sol";

contract TestPlonk {
    function test_eval_l_1() external {
        uint64[2] memory x;
        x[0] = 9076502759914437505;
        x[1] = 16396680756479675411;
        uint64[2] memory res = PlonkLib.eval_l_1(4096, x);
        require(res[0] == 15052319864161058789);
        require(res[1] == 16841416332519902625);
    }
}
