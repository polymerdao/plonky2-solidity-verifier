// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksField.sol";

library GoldilocksExtLib {
    using GoldilocksFieldLib for uint64;

    uint64 constant W = 7;

    function one() internal pure returns (uint64[2] memory res) {
        res[0] = 1;
    }

    function add(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
    }

    function sub(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
    }

    function mul(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
        uint128 cumul_lo;
        uint32 cumul_hi;
        bool cy;
        (cumul_lo, cumul_hi) = u160_times_7(uint128(a[1]) * uint128(b[1]), 0);
        (cumul_lo, cy) = u128_overflowing_add(cumul_lo, uint128(a[0]) * uint128(b[0]));
        if (cy) cumul_hi += 1;
        res[0] = GoldilocksFieldLib.reduce160(cumul_lo, cumul_hi);

        cumul_lo = uint128(a[0]) * uint128(b[1]);
        (cumul_lo, cy) = u128_overflowing_add(cumul_lo, uint128(a[1]) * uint128(b[0]));
        cumul_hi = 0;
        if (cy) cumul_hi = 1;
        res[1] = GoldilocksFieldLib.reduce160(cumul_lo, cumul_hi);
        return res;
    }

    function div(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
    }

    function square(uint64[2] memory a) internal pure returns (uint64[2] memory res) {
        res[0] = a[0].square().add(W.mul(a[1].square()));
        res[1] = a[0].mul(a[1].double());
        return res;
    }

    function exp(uint64[2] memory x, uint64 n) internal pure returns (uint64[2] memory) {
        uint64[2] memory product = one();
        uint32 shift = 0;
        while ((n << shift) <= n) {
            if ((n >> shift) & 1 > 0) {
                product = mul(product, x);
            }
            x = square(x);
            shift++;
        }
        return product;
    }

    function u128_overflowing_add(uint128 a, uint128 b) internal pure returns (uint128, bool) {
        uint128 sum = 0;
        bool over = false;
    unchecked {
        sum = a + b;
    }
        if (sum < a || sum < b) {
            over = true;
        }
        return (sum, over);
    }

    function u128_overflowing_sub(uint128 a, uint128 b) internal pure returns (uint128, bool) {
        uint128 diff = 0;
        bool under = false;
        if (a < b) {
            under = true;
        }
    unchecked {
        diff = a - b;
    }
        return (diff, under);
    }

    /// Return a, b such that a + b*2^128 = 7*x with a < 2^128 and b < 2^32.
    function u160_times_7(uint128 x, uint32 y) internal pure returns (uint128, uint32) {
        uint128 d;
        bool br;
        (d, br) = u128_overflowing_sub(x << 3, x);
        uint32 e = 7 * y + uint32(x >> (128 - 3));
        if (br) e -= 1;
        return (d, e);
    }
}
