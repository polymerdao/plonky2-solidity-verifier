// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library GoldilocksFieldLib {
    uint64 constant EPSILON = 4294967295;  // (1 << 32) - 1
    uint64 constant ORDER = 18446744069414584321;
    uint32 constant CHARACTERISTIC_TWO_ADICITY = 32;
    uint64 constant INVERSE_2_POW_ADICITY = 18446744065119617026;

    function mul(uint64 a, uint64 b) internal pure returns (uint64) {
        return reduce128(uint128(a) * uint128(b));
    }

    function div(uint64 a, uint64 b) internal pure returns (uint64) {
        return mul(a, inverse(b));
    }

    function square(uint64 a) internal pure returns (uint64) {
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

    function exp(uint64 x, uint64 n) internal pure returns (uint64) {
        uint64 product = 1;
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

    function safe_iteration(uint64 f, uint64 g, int128 c, int128 d, uint32 k) internal pure returns (uint64, uint64, int128, int128, uint32) {
        if (f < g) {
            (f, g) = (g, f);
            (c, d) = (d, c);
        }
        if (f & 3 == g & 3) {
            // f - g = 0 (mod 4)
            f -= g;
            c -= d;
            // kk >= 2 because f is now 0 (mod 4).
            uint32 kk = trailing_zeros(f);
            f = f >> kk;
            d = d << kk;
            k += kk;
        } else {
            // f + g = 0 (mod 4)
            f = (f >> 2) + (g >> 2) + 1;
            c += d;
            uint32 kk = trailing_zeros(f);
            f = f >> kk;
            d = d << (kk + 2);
            k += kk + 2;
        }
        return (f, g, c, d, k);
    }

    function unsafe_iteration(uint64 f, uint64 g, int128 c, int128 d, uint32 k) internal pure returns (uint64, uint64, int128, int128, uint32) {
        if (f < g) {
            (f, g) = (g, f);
            (c, d) = (d, c);
        }
        if (f & 3 == g & 3) {
            // f - g = 0 (mod 4)
            f -= g;
            c -= d;
        } else {
            // f + g = 0 (mod 4)
            f += g;
            c += d;
        }
        // kk >= 2 because f is now 0 (mod 4).
        uint32 kk = trailing_zeros(f);
        f = f >> kk;
        d = d << kk;
        k += kk;
        return (f, g, c, d, k);
    }

    function inverse(uint64 f) internal pure returns (uint64) {
        require(f != 0);
        uint64 g = ORDER;
        int128 c = 1;
        int128 d = 0;

        uint32 k = trailing_zeros(f);
        f = f >> k;
        if (f == 1) {
            return inverse_2exp(k);
        }

        (f, g, c, d, k) = safe_iteration(f, g, c, d, k);

        if (f == 1) {
            // c must be -1 or 1 here.
            if (c == - 1) {
                return sub(0, inverse_2exp(k));
            }
            return inverse_2exp(k);
        }

        (f, g, c, d, k) = safe_iteration(f, g, c, d, k);
        while (f != 1) {
            (f, g, c, d, k) = unsafe_iteration(f, g, c, d, k);
        }

        while (c < 0) {
            c += int128(uint128(ORDER));
        }

        while (c >= int128(uint128(ORDER))) {
            c -= int128(uint128(ORDER));
        }

        return mul(uint64(uint128(c)), inverse_2exp(k));
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
        uint64 x_hi = uint64(_x_lo >> 96) + (uint64(_x_hi) << 32);
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
