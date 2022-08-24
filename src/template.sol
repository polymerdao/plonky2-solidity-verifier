// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Import this file to use console.log
import "hardhat/console.sol";
import {ChallengerLib} from "./Challenger.sol";

contract Plonky2Verifier {
    using ChallengerLib for ChallengerLib.Challenger;

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
    uint32 constant NUM_FRI_QUERY_INIT_WIRES_V = $NUM_FRI_QUERY_INIT_WIRES_V;
    uint32 constant NUM_FRI_QUERY_INIT_WIRES_P = $NUM_FRI_QUERY_INIT_WIRES_P;
    uint32 constant NUM_FRI_QUERY_INIT_ZS_PARTIAL_V = $NUM_FRI_QUERY_INIT_ZS_PARTIAL_V;
    uint32 constant NUM_FRI_QUERY_INIT_ZS_PARTIAL_P = $NUM_FRI_QUERY_INIT_ZS_PARTIAL_P;
    uint32 constant NUM_FRI_QUERY_INIT_QUOTIENT_V = $NUM_FRI_QUERY_INIT_QUOTIENT_V;
    uint32 constant NUM_FRI_QUERY_INIT_QUOTIENT_P = $NUM_FRI_QUERY_INIT_QUOTIENT_P;
    uint32 constant NUM_FRI_QUERY_STEP0_V = $NUM_FRI_QUERY_STEP0_V;
    uint32 constant NUM_FRI_QUERY_STEP0_P = $NUM_FRI_QUERY_STEP0_P;
    uint32 constant NUM_FRI_QUERY_STEP1_V = $NUM_FRI_QUERY_STEP1_V;
    uint32 constant NUM_FRI_QUERY_STEP1_P = $NUM_FRI_QUERY_STEP1_P;
    uint32 constant NUM_FRI_FINAL_POLY_EXT_V = $NUM_FRI_FINAL_POLY_EXT_V;

    bytes25 constant CIRCUIT_DIGEST = $CIRCUIT_DIGEST;
    uint32 constant NUM_CHALLENGES = $NUM_CHALLENGES;
    uint32 constant FRI_RATE_BITS = $FRI_RATE_BITS;
    uint32 constant DEGREE_BITS = $DEGREE_BITS;
    uint32 constant NUM_GATE_CONSTRAINTS = 4; // TODO(): fix it

    struct Proof {
        bytes25[] wires_cap;
        bytes25[] plonk_zs_partial_products_cap;
        bytes25[] quotient_polys_cap;

        bytes16[] openings_constants;
        bytes16[] openings_plonk_sigmas;
        bytes16[] openings_wires;
        bytes16[] openings_plonk_zs;
        bytes16[] openings_plonk_zs_next;
        bytes16[] openings_partial_products;
        bytes16[] openings_quotient_polys;

        bytes25[][] fri_commit_phase_merkle_caps;
        bytes8[][] fri_query_init_constants_sigmas_v;
        bytes25[][] fri_query_init_constants_sigmas_p;
        bytes8[][] fri_query_init_wires_v;
        bytes25[][] fri_query_init_wires_p;
        bytes8[][] fri_query_init_zs_partial_v;
        bytes25[][] fri_query_init_zs_partial_p;
        bytes8[][] fri_query_init_quotient_v;
        bytes25[][] fri_query_init_quotient_p;
        bytes16[][] fri_query_step0_v;
        bytes25[][] fri_query_step0_p;
        bytes16[][] fri_query_step1_v;
        bytes25[][] fri_query_step1_p;

        bytes16[] fri_final_poly_ext_v;
        bytes8 fri_pow_witness;
    }

    struct ProofChallenges {
        bytes8[] plonk_betas;
        bytes8[] plonk_gammas;
        bytes8[] plonk_alphas;
        bytes16[] plonk_zeta;
        bytes16 fri_alpha;
        bytes16[] fri_betas;
        bytes8 fri_pow_response;
        bytes8[] fri_query_indices;
    }

    function get_sigma_cap() internal pure returns (bytes25[SIGMAS_CAP_COUNT] memory sc) {
        $SET_SIGMA_CAP;
    }

    function reverse(uint64 input) internal pure returns (uint64 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00FF00FF00) >> 8) |
        ((v & 0x00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        v = ((v & 0xFFFF0000FFFF0000) >> 16) |
        ((v & 0x0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        v = (v >> 32) | (v << 32);
    }

    function get_fri_pow_response(ChallengerLib.Challenger memory challenger, bytes8 pow_witness) internal pure returns (uint64 res) {
        uint64 u1 = challenger.get_challenge();
        uint64 u2 = challenger.get_challenge();
        uint64 u3 = challenger.get_challenge();
        uint64 u4 = challenger.get_challenge();
        uint64 u5 = uint64(pow_witness);

        ChallengerLib.Challenger memory new_challenger;
        new_challenger.observe_element(bytes8(reverse(u1)));
        new_challenger.observe_element(bytes8(reverse(u2)));
        new_challenger.observe_element(bytes8(reverse(u3)));
        new_challenger.observe_element(bytes8(reverse(u4)));
        new_challenger.observe_element(bytes8(u5));

        res = new_challenger.get_challenge();
    }

    function verify(Proof calldata proof_with_public_inputs) public view returns (bool) {
        require(proof_with_public_inputs.wires_cap.length == NUM_WIRES_CAP);
        require(proof_with_public_inputs.plonk_zs_partial_products_cap.length == NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP);
        require(proof_with_public_inputs.quotient_polys_cap.length == NUM_QUOTIENT_POLYS_CAP);
        require(proof_with_public_inputs.openings_constants.length == NUM_OPENINGS_CONSTANTS);
        require(proof_with_public_inputs.openings_plonk_sigmas.length == NUM_OPENINGS_PLONK_SIGMAS);
        require(proof_with_public_inputs.openings_wires.length == NUM_OPENINGS_WIRES);
        require(proof_with_public_inputs.openings_plonk_zs.length == NUM_OPENINGS_PLONK_ZS);
        require(proof_with_public_inputs.openings_plonk_zs_next.length == NUM_OPENINGS_PLONK_ZS_NEXT);
        require(proof_with_public_inputs.openings_partial_products.length == NUM_OPENINGS_PARTIAL_PRODUCTS);
        require(proof_with_public_inputs.openings_quotient_polys.length == NUM_OPENINGS_QUOTIENT_POLYS);

        require(proof_with_public_inputs.fri_commit_phase_merkle_caps.length == NUM_FRI_COMMIT_ROUND);
        require(proof_with_public_inputs.fri_query_init_constants_sigmas_v.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_constants_sigmas_p.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_wires_v.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_wires_p.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_zs_partial_v.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_zs_partial_p.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_quotient_v.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_init_quotient_p.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_step0_v.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_step0_p.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_step1_v.length == NUM_FRI_QUERY_ROUND);
        require(proof_with_public_inputs.fri_query_step1_p.length == NUM_FRI_QUERY_ROUND);

        require(proof_with_public_inputs.fri_final_poly_ext_v.length == NUM_FRI_FINAL_POLY_EXT_V);

        ChallengerLib.Challenger memory challenger;
        bytes25 input_hash = 0;
        challenger.observe_hash(CIRCUIT_DIGEST);
        challenger.observe_hash(input_hash);
        for (uint32 i = 0; i < NUM_WIRES_CAP; i++) {
            challenger.observe_hash(proof_with_public_inputs.wires_cap[i]);
        }
        uint64[] memory plonk_betas = challenger.get_challenges(NUM_CHALLENGES);
        uint64[] memory plonk_gammas = challenger.get_challenges(NUM_CHALLENGES);

        for (uint32 i = 0; i < NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP; i++) {
            challenger.observe_hash(proof_with_public_inputs.plonk_zs_partial_products_cap[i]);
        }
        uint64[] memory plonk_alphas = challenger.get_challenges(NUM_CHALLENGES);
        console.log(plonk_betas[0]);
        console.log(plonk_gammas[0]);
        console.log(plonk_alphas[0]);

        for (uint32 i = 0; i < NUM_QUOTIENT_POLYS_CAP; i++) {
            challenger.observe_hash(proof_with_public_inputs.quotient_polys_cap[i]);
        }
        uint64[2] memory plonk_zeta = challenger.get_extension_challenge();
        console.log(plonk_zeta[0], plonk_zeta[1]);

        for (uint32 i = 0; i < NUM_OPENINGS_CONSTANTS; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_constants[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_SIGMAS; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_plonk_sigmas[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_WIRES; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_wires[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_ZS; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_plonk_zs[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PARTIAL_PRODUCTS; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_partial_products[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_QUOTIENT_POLYS; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_quotient_polys[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_ZS_NEXT; i++) {
            challenger.observe_extension(proof_with_public_inputs.openings_plonk_zs_next[i]);
        }

        // TODO: implement constraint_terms = evaluate_gate_constraints()
        uint64[2][NUM_GATE_CONSTRAINTS] memory constraint_terms;
        // vanishing_z_1_terms;
        // vanishing_partial_products_terms;
        // l1_x;

        // Fri Challenges
        uint64[2] memory fri_alpha = challenger.get_extension_challenge();
        console.log(fri_alpha[0], fri_alpha[1]);
        uint64[NUM_FRI_COMMIT_ROUND][2] memory fri_betas;
        for (uint32 i = 0; i < NUM_FRI_COMMIT_ROUND; i++) {
            for (uint32 j = 0; j < FRI_COMMIT_MERKLE_CAP_HEIGHT; j++) {
                challenger.observe_hash(proof_with_public_inputs.fri_commit_phase_merkle_caps[i][j]);
            }
            fri_betas[i] = challenger.get_extension_challenge();
            console.log(fri_betas[i][0], fri_betas[i][1]);
        }

        for (uint32 i = 0; i < NUM_FRI_FINAL_POLY_EXT_V; i++) {
            challenger.observe_extension(proof_with_public_inputs.fri_final_poly_ext_v[i]);
        }

        uint64 fri_pow_response = get_fri_pow_response(challenger, proof_with_public_inputs.fri_pow_witness);
        console.log(fri_pow_response);
        uint32[] memory fri_query_indices = new uint32[](NUM_FRI_QUERY_ROUND);
        uint32 lde_size = uint32(1 << (DEGREE_BITS + FRI_RATE_BITS));
        for (uint32 i = 0; i < NUM_FRI_QUERY_ROUND; i++) {
            uint32 ele = uint32(challenger.get_challenge());
            fri_query_indices[i] = ele % lde_size;
            console.log(fri_query_indices[i]);
        }

        bytes25[SIGMAS_CAP_COUNT] memory sc = get_sigma_cap();
        console.logBytes25(sc[0]);

        console.logBytes25(proof_with_public_inputs.wires_cap[0]);

        console.logBytes16(proof_with_public_inputs.openings_quotient_polys[0]);
        console.logBytes8(proof_with_public_inputs.fri_query_init_constants_sigmas_v[0][0]);
        console.logBytes25(proof_with_public_inputs.fri_query_init_constants_sigmas_p[0][0]);
        console.logBytes8(proof_with_public_inputs.fri_query_init_quotient_v[0][0]);
        console.logBytes25(proof_with_public_inputs.fri_query_init_quotient_p[0][0]);
        console.logBytes16(proof_with_public_inputs.fri_query_step1_v[0][0]);
        console.logBytes25(proof_with_public_inputs.fri_query_step1_p[0][0]);
        console.logBytes8(proof_with_public_inputs.fri_pow_witness);
        return true;
    }
}
