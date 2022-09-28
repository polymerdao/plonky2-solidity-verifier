// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library GoldilocksFieldLib {
    uint64 constant EPSILON = 4294967295;  // (1 << 32) - 1
    uint64 constant ORDER = 18446744069414584321;
    uint32 constant CHARACTERISTIC_TWO_ADICITY = 32;
    uint64 constant INVERSE_2_POW_ADICITY = 18446744065119617026;

    function expmod(uint64 base, uint64 exponent, uint64 modulus) internal view returns (uint64 res) {
        assembly {
            let p := mload(0x40)
            mstore(p, 0x20) // Length of Base.
            mstore(add(p, 0x20), 0x20) // Length of Exponent.
            mstore(add(p, 0x40), 0x20) // Length of Modulus.
            mstore(add(p, 0x60), base) // Base.
            mstore(add(p, 0x80), exponent) // Exponent.
            mstore(add(p, 0xa0), modulus) // Modulus.
        // Call modexp precompile.
            if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) {
                revert(0, 0)
            }
            res := mload(p)
        }
    }

    function mul(uint64 a, uint64 b) internal pure returns (uint64 res) {
        assembly {
            res := mulmod(a, b, ORDER)
        }
    }

    function div(uint64 a, uint64 b) internal view returns (uint64) {
        return mul(a, inverse(b));
    }

    function square(uint64 a) internal pure returns (uint64) {
        return mul(a, a);
    }

    function add(uint64 a, uint64 b) internal pure returns (uint64 res) {
        assembly {
            res := addmod(a, b, ORDER)
        }
    }

    function sub(uint64 a, uint64 b) internal pure returns (uint64 res) {
        assembly {
            res := addmod(a, sub(ORDER, b), ORDER)
        }
    }

    function double(uint64 a) internal pure returns (uint64 res) {
        return add(a, a);
    }

    function exp(uint64 x, uint64 n) internal view returns (uint64) {
        return expmod(x, n, ORDER);
    }

    function exp_power_of_2(uint64 a, uint32 power_log) internal pure returns (uint64 res) {
        res = a;
        for (uint32 i = 0; i < power_log; i++) {
            res = square(res);
        }
        return res;
    }

    function trailing_zeros(uint64 a) internal pure returns (uint32 res) {
        if (a == 0) return 0;
        while (a & 1 == 0) {
            a = a >> 1;
            res++;
        }
        return res;
    }

    /// Compute the inverse of 2^x in this field.
    function inverse_2exp(uint32 x) internal pure returns (uint64) {
        if (x > CHARACTERISTIC_TWO_ADICITY) {
            uint64 res = INVERSE_2_POW_ADICITY;
            uint32 e = x - CHARACTERISTIC_TWO_ADICITY;
            while (e > CHARACTERISTIC_TWO_ADICITY) {
                res = mul(res, INVERSE_2_POW_ADICITY);
                e -= CHARACTERISTIC_TWO_ADICITY;
            }
            return mul(res, ORDER - ((ORDER - 1) >> uint64(e)));
        } else {
            return ORDER - ((ORDER - 1) >> uint64(x));
        }
    }

    function inverse(uint64 f) internal view returns (uint64) {
        return expmod(f, ORDER - 2, ORDER);
    }
}
