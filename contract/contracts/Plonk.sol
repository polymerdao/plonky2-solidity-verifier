// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksExt.sol";

library PlonkLib {
    using GoldilocksExtLib for uint64[2];
    function eval_l_1(uint64 n, uint64[2] memory x) internal view returns (uint64[2] memory res) {
        if (x[0] == 1 && x[1] == 0) {
            return x;
        }
        uint64[2] memory d;
        d[0] = n;
        uint64[2] memory one = GoldilocksExtLib.one();
        return x.exp(n).sub(one).div(d.mul(x.sub(one)));
    }
}
