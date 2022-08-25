// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./Plonk.sol";

contract TestPlonk {
    function test_eval_l_1() public pure returns (uint64[2] memory) {
        uint64[2] memory x;
        x[0] = 9076502759914437505;
        x[1] = 16396680756479675411;
        return PlonkLib.eval_l_1(4096, x);
    }
}
