// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import "./GoldilocksField.sol";

library GoldilocksExtLib {
    using GoldilocksFieldLib for uint64;

    uint64 constant W = 7;
    uint64 constant DTH_ROOT = 18446744069414584320;

    function equal(uint64[2] memory a, uint64[2] memory b) internal pure returns (bool res) {
        res = a[0] == b[0];
        res = res && a[1] == b[1];
    }

    function one() internal pure returns (uint64[2] memory res) {
        res[0] = 1;
        return res;
    }

    function add(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
        res[0] = a[0].add(b[0]);
        res[1] = a[1].add(b[1]);
        return res;
    }

    function sub(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
        res[0] = a[0].sub(b[0]);
        res[1] = a[1].sub(b[1]);
        return res;
    }

    function mul(uint64[2] memory a, uint64[2] memory b) internal pure returns (uint64[2] memory res) {
        res[0] = a[0].mul(b[0]).add(W.mul(a[1].mul(b[1])));
        res[1] = a[0].mul(b[1]).add(a[1].mul(b[0]));
        return res;
    }

    function div(uint64[2] memory a, uint64[2] memory b) internal view returns (uint64[2] memory res) {
        return mul(a, inverse(b));
    }

    function scalar_mul(uint64[2] memory a, uint64 scalar) internal pure returns (uint64[2] memory res) {
        res[0] = a[0].mul(scalar);
        res[1] = a[1].mul(scalar);
        return res;
    }

    function inverse(uint64[2] memory a) internal view returns (uint64[2] memory res) {
        require(a[0] != 0 && a[1] != 0);
        uint64[2] memory a_pow_r_minus_1 = repeated_frobenius(a, 1);
        uint64[2] memory a_pow_r = mul(a_pow_r_minus_1, a);
        res = scalar_mul(a_pow_r_minus_1, a_pow_r[0].inverse());
        return res;
    }

    function repeated_frobenius(uint64[2] memory a, uint32 count) internal pure returns (uint64[2] memory res) {
        if (count == 0) {
            return a;
        } else if (count >= 2) {
            return repeated_frobenius(a, count % 2);
        }
        res[0] = a[0].mul(1);
        res[1] = a[1].mul(DTH_ROOT);
        return res;
    }

    function square(uint64[2] memory a) internal pure returns (uint64[2] memory res) {
        res[0] = a[0].square().add(W.mul(a[1].square()));
        res[1] = a[0].mul(a[1].double());
        return res;
    }

    function exp_power_of_2(uint64[2] memory a, uint32 power_log) internal pure returns (uint64[2] memory res) {
        res = a;
        for (uint32 i = 0; i < power_log; i++) {
            res = square(res);
        }
        return res;
    }

    function exp(uint64[2] memory x, uint64 n) internal pure returns (uint64[2] memory) {
        if (x[0] == 0 && x[1] == 0) return x;
        uint64[2] memory product = one();
        uint32 shift = 0;
        while ((1 << shift) <= n) {
            if ((n >> shift) & 1 > 0) {
                product = mul(product, x);
            }
            x = square(x);
            shift++;
        }
        return product;
    }
}
