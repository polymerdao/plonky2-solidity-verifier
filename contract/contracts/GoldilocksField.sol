// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library GoldilocksFieldLib {
    uint64 constant EPSILON = 4294967295;  // (1 << 32) - 1

    function mul(uint64 a, uint64 b) internal pure returns (uint64) {
        return reduce128(uint128(a) * uint128(b));
    }

    function div(uint64 a, uint64 b) internal pure returns (uint64 res) {
    }

    function square(uint64 a) internal pure returns (uint64 res) {
        return mul(a, a);
    }

    function overflowing_sub(uint64 a, uint64 b) internal pure returns (uint64, bool) {
        uint64 diff = 0;
        bool under = false;
        if (a < b) {
            under = true;
        }
    unchecked {
        diff = a - b;
    }
        return (diff, under);
    }

    function overflowing_add(uint64 a, uint64 b) internal pure returns (uint64, bool) {
        uint64 sum = 0;
        bool over = false;
    unchecked {
        sum = a + b;
    }
        if (sum < a || sum < b) {
            over = true;
        }
        return (sum, over);
    }

    function add(uint64 a, uint64 b) internal pure returns (uint64) {
        uint64 sum;
        bool over;
        (sum, over) = overflowing_add(a, b);
        if (over) {
            (sum, over) = overflowing_add(sum, EPSILON);
        }
        if (over) {
            sum += EPSILON;
        }
        return sum;
    }

    function sub(uint64 a, uint64 b) internal pure returns (uint64) {
        uint64 diff;
        bool under;
        (diff, under) = overflowing_sub(a, b);
        if (under) {
            (diff, under) = overflowing_sub(diff, EPSILON);
        }
        if (under) {
            diff -= EPSILON;
        }
        return diff;
    }

    function double(uint64 a) internal pure returns (uint64 res) {
        return add(a, a);
    }

    // Reduces to a 64-bit value. The result might not be in canonical form;
    // it could be in between the field order and `2^64`.
    function reduce128(uint128 x) internal pure returns (uint64) {
        uint64 x_lo = uint64(x);
        uint64 x_hi = uint64(x >> 64);
        uint64 x_hi_hi = x_hi >> 32;
        uint64 x_hi_lo = x_hi & EPSILON;
        uint64 t0;
        bool over;
        (t0, over) = overflowing_sub(x_lo, x_hi_hi);
        if (over) {
            t0 -= EPSILON;
        }
        uint64 t1 = x_hi_lo * EPSILON;
        uint64 t2;
        (t2, over) = overflowing_add(t0, t1);
        if (over) {
            t2 += EPSILON;
        }
        return t2;
    }

    // Reduces to a 64-bit value. The correctness relies on the
    // unchecked assumption that x < 2^160 - 2^128 + 2^96
    function reduce160(uint128 _x_lo, uint32 _x_hi) internal pure returns (uint64) {
        uint64 x_hi = uint64(_x_lo >> 96) + uint64(_x_hi) << 32;
        uint32 x_mid = uint32(_x_lo >> 64);
        uint64 x_lo = uint64(_x_lo);

        uint64 t0;
        bool over;
        (t0, over) = overflowing_sub(x_lo, x_hi);
        if (over) {
            t0 -= EPSILON;
        }
        uint64 t1 = uint64(x_mid) * EPSILON;
        uint64 t2;
        (t2, over) = overflowing_add(t0, t1);
        if (over) {
            t2 += EPSILON;
        }
        return t2;
    }
}
