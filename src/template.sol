// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Import this file to use console.log
import "hardhat/console.sol";

contract Plonky2Verifier {
    uint32 constant SIGMAS_CAP_COUNT = $SIGMA_CAP_COUNT;

    uint32 constant NUM_WIRES_CAP = $NUM_WIRES_CAP;
    uint32 constant NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP = $NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP;
    uint32 constant NUM_QUOTIENT_POLYS_CAP = $NUM_QUOTIENT_POLYS_CAP;

    uint32 constant NUM_OPENINGS_CONSTANTS = $NUM_OPENINGS_CONSTANTS;
    uint32 constant NUM_OPENINGS_PLONK_SIGMAS = $NUM_OPENINGS_PLONK_SIGMAS;

    struct Proof {
        bytes25[NUM_WIRES_CAP] wires_cap;
        bytes25[NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP] plonk_zs_partial_products_cap;
        bytes25[NUM_QUOTIENT_POLYS_CAP] quotient_polys_cap;
        bytes16[NUM_OPENINGS_CONSTANTS] openings_constants;
        bytes16[NUM_OPENINGS_PLONK_SIGMAS] openings_plonk_sigmas;
        uint8[] rest_bytes;
    }

    function get_sigma_cap() internal pure returns (bytes25[SIGMAS_CAP_COUNT] memory sc) {
        $SET_SIGMA_CAP;
    }

    function verify(Proof memory proof_with_public_inputs) public view returns (bool) {
        bytes25[SIGMAS_CAP_COUNT] memory sc = get_sigma_cap();
        console.logBytes25(sc[0]);

        console.logBytes25(proof_with_public_inputs.wires_cap[0]);
        console.logBytes16(proof_with_public_inputs.openings_plonk_sigmas[0]);

        console.log(proof_with_public_inputs.rest_bytes.length);
        return true;
    }
}
