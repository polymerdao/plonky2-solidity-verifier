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
    uint32 constant NUM_OPENINGS_WIRES = $NUM_OPENINGS_WIRES;
    uint32 constant NUM_OPENINGS_PLONK_ZS = $NUM_OPENINGS_PLONK_ZS0;
    uint32 constant NUM_OPENINGS_PLONK_ZS_NEXT = $NUM_OPENINGS_PLONK_ZS_NEXT;
    uint32 constant NUM_OPENINGS_PARTIAL_PRODUCTS = $NUM_OPENINGS_PARTIAL_PRODUCTS;
    uint32 constant NUM_OPENINGS_QUOTIENT_POLYS = $NUM_OPENINGS_QUOTIENT_POLYS;

    uint32 constant NUM_FRI_COMMIT_ROUND = $NUM_FRI_COMMIT_ROUND;
    uint32 constant FRI_COMMIT_MERKLE_CAP_HEIGHT = $FRI_COMMIT_MERKLE_CAP_HEIGHT;
    uint32 constant NUM_FRI_QUERY_ROUND = $NUM_FRI_QUERY_ROUND;
    uint32 constant NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_V = $NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_V;
    uint32 constant NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_P = $NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_P;

    struct Proof {
        bytes25[NUM_WIRES_CAP] wires_cap;
        bytes25[NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP] plonk_zs_partial_products_cap;
        bytes25[NUM_QUOTIENT_POLYS_CAP] quotient_polys_cap;

        bytes16[NUM_OPENINGS_CONSTANTS] openings_constants;
        bytes16[NUM_OPENINGS_PLONK_SIGMAS] openings_plonk_sigmas;
        bytes16[NUM_OPENINGS_WIRES] openings_wires;
        bytes16[NUM_OPENINGS_PLONK_ZS] openings_plonk_zs;
        bytes16[NUM_OPENINGS_PLONK_ZS_NEXT] openings_plonk_zs_next;
        bytes16[NUM_OPENINGS_PARTIAL_PRODUCTS] openings_partial_products;
        bytes16[NUM_OPENINGS_QUOTIENT_POLYS] openings_quotient_polys;

        bytes25[NUM_FRI_COMMIT_ROUND][FRI_COMMIT_MERKLE_CAP_HEIGHT] commit_phase_merkle_caps;

        uint8[] rest_bytes;
    }

    function get_sigma_cap() internal pure returns (bytes25[SIGMAS_CAP_COUNT] memory sc) {
        $SET_SIGMA_CAP;
    }

    function verify(Proof memory proof_with_public_inputs) public view returns (bool) {
        bytes25[SIGMAS_CAP_COUNT] memory sc = get_sigma_cap();
        console.logBytes25(sc[0]);

        console.logBytes25(proof_with_public_inputs.wires_cap[0]);

        console.logBytes25(proof_with_public_inputs.commit_phase_merkle_caps[0][0]);
        return true;
    }
}
