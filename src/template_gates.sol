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

    function wires_algebra_mul(uint64[2][$NUM_OPENINGS_WIRES] memory wires, uint32 l, uint32 r)
    internal pure returns(uint64[2][$D] memory res) {{
        uint64[2] memory w;
        w[0] = $F_EXT_W;
        for (uint32 i = 0; i < $D; i++) {{
            for (uint32 j = 0; j < $D; j++) {{
                if (i + j < $D) {{
                    res[(i + j) % $D] = res[(i + j) % $D].add(wires[l + i].mul(wires[r + j]));
                }} else {{
                    res[(i + j) % $D] = res[(i + j) % $D].add(w.mul(wires[l + i]).mul(wires[r + j]));
                }}
            }}
        }}
    }}
}
