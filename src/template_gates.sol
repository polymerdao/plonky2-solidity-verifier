// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksField.sol";
import "./GoldilocksExt.sol";

library GatesUtilsLib {
    using GoldilocksFieldLib for uint64;
    using GoldilocksExtLib for uint64[2];
    function push(uint64[2][$NUM_GATE_CONSTRAINTS] memory constraints,
        uint64[2] memory filter, uint32 index, uint64[2] memory value)
    internal pure {
        constraints[index] = constraints[index].add(value.mul(filter));
    }
}

