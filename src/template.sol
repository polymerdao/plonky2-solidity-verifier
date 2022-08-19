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

    uint32 constant SPONGE_RATE = 8;
    uint32 constant SPONGE_CAPACITY = 4;
    uint32 constant SPONGE_WIDTH = 12;

    struct Challenger {
        bytes8[] input_buf;
        bytes8[] output_buf;
        bytes8[SPONGE_WIDTH] sponge_state;
    }

    function elementToLeBytes(uint64 input) internal pure returns (bytes8 res) {
        res = bytes8(input >> 56) & 0x00000000000000FF;
        res = res | (bytes8(input >> 40) & 0x000000000000FF00);
        res = res | (bytes8(input >> 24) & 0x0000000000FF0000);
        res = res | (bytes8(input >> 8) & 0x00000000FF000000);
        res = res | (bytes8(input << 8) & 0x000000FF00000000);
        res = res | (bytes8(input << 24) & 0x0000FF0000000000);
        res = res | (bytes8(input << 40) & 0x00FF000000000000);
        res = res | (bytes8(input << 56) & 0xFF00000000000000);
        return res;
    }

    function toBytes8(bytes memory _bytes, uint256 _start) internal pure returns (bytes8) {
        require(_bytes.length >= _start + 8, "toBytes8_outOfBounds");
        bytes8 tempBytes8;

        assembly {
            tempBytes8 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes8;
    }

    function keccak_permutation(bytes8[SPONGE_WIDTH] memory input) internal pure returns (bytes8[SPONGE_WIDTH] memory res) {
        bytes32 h = keccak256(abi.encodePacked(input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
            input[8], input[9], input[10], input[11]));
        bytes32 hh = keccak256(abi.encodePacked(h));
        bytes32 hhh = keccak256(abi.encodePacked(hh));
        bytes memory tmp = abi.encodePacked(h, hh, hhh);
        uint8 pos = 0;

        for (uint i = 0; i < SPONGE_WIDTH * 8; i = i + 8) {
            bytes8 b = toBytes8(tmp, i);
            // check bytes in the field order
            if ((b & 0x00000000FFFFFFFF) != 0x00000000FFFFFFFF) {
                res[pos++] = b;
            }
        }

        return res;
    }

    function log_input(Challenger memory challenger) internal view {
        for (uint i = 0; i < challenger.input_buf.length; i++) {
            console.logBytes8(challenger.input_buf[i]);
        }
    }

    function log_sponge_state(Challenger memory challenger) internal view {
        for (uint i = 0; i < 12; i++) {
            console.logBytes8(challenger.sponge_state[i]);
        }
    }

    function challenger_duplexing(Challenger memory challenger) internal pure {
        require(challenger.input_buf.length <= SPONGE_RATE);
        for (uint i = 0; i < challenger.input_buf.length; i++) {
            challenger.sponge_state[i] = challenger.input_buf[i];
        }
        delete challenger.input_buf;
        challenger.sponge_state = keccak_permutation(challenger.sponge_state);
        delete challenger.output_buf;
        challenger.output_buf = new bytes8[](SPONGE_RATE);
        for (uint i = 0; i < SPONGE_RATE; i++) {
            challenger.output_buf[i] = challenger.sponge_state[i];
        }
    }

    function challenger_observe_element(Challenger memory challenger, bytes8 element) internal pure {
        delete challenger.output_buf;
        bytes8[] memory input = new bytes8[](challenger.input_buf.length + 1);
        for (uint32 i = 0; i < input.length - 1; i++) {
            input[i] = challenger.input_buf[i];
        }
        input[input.length - 1] = element;
        delete challenger.input_buf;
        challenger.input_buf = input;
        if (challenger.input_buf.length == SPONGE_RATE) {
            challenger_duplexing(challenger);
        }
    }

    function challenger_observe_extension(Challenger memory challenger, bytes16 ext) internal pure {
        bytes8 element = bytes8(ext);
        challenger_observe_element(challenger, element);
        element = bytes8(ext << 64);
        challenger_observe_element(challenger, element);
    }

    function challenger_observe_hash(Challenger memory challenger, bytes25 hash) internal pure {
        bytes8 b0 = bytes8(hash);
        bytes8 b1 = bytes8(hash << 56);
        bytes8 b2 = bytes8(hash << 112);
        bytes8 b3 = bytes8(hash << 168);
        b0 = b0 & 0xFFFFFFFFFFFFFF00;
        b1 = b1 & 0xFFFFFFFFFFFFFF00;
        b2 = b2 & 0xFFFFFFFFFFFFFF00;
        b3 = b3 & 0xFFFFFFFF00000000;

        challenger_observe_element(challenger, b0);
        challenger_observe_element(challenger, b1);
        challenger_observe_element(challenger, b2);
        challenger_observe_element(challenger, b3);
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

    function challenger_get_challenge(Challenger memory challenger) internal pure returns (uint64 res) {
        if (challenger.input_buf.length > 0 || challenger.output_buf.length == 0) {
            challenger_duplexing(challenger);
        }
        res = reverse(uint64(challenger.output_buf[challenger.output_buf.length - 1]));
        bytes8[] memory output = new bytes8[](challenger.output_buf.length - 1);
        for (uint32 i = 0; i < output.length; i++) {
            output[i] = challenger.output_buf[i];
        }
        delete challenger.output_buf;
        challenger.output_buf = output;
        return res;
    }

    function challenger_get_challenges(Challenger memory challenger, uint32 num) internal pure returns (uint64[] memory) {
        uint64[] memory res = new uint64[](num);
        for (uint i = 0; i < num; i++) {
            res[i] = challenger_get_challenge(challenger);
        }
        return res;
    }

    function get_extension_challenge(Challenger memory challenger) internal pure returns (uint64[2] memory res) {
        res[0] = challenger_get_challenge(challenger);
        res[1] = challenger_get_challenge(challenger);
    }

    function get_fri_pow_response(Challenger memory challenger, bytes8 pow_witness) internal pure returns (uint64 res) {
    }

    function verify(Proof memory proof_with_public_inputs) public view returns (bool) {
        Challenger memory challenger;
        bytes25 input_hash = 0;
        challenger_observe_hash(challenger, CIRCUIT_DIGEST);
        challenger_observe_hash(challenger, input_hash);
        for (uint32 i = 0; i < NUM_WIRES_CAP; i++) {
            challenger_observe_hash(challenger, proof_with_public_inputs.wires_cap[i]);
        }
        uint64[] memory plonk_betas = challenger_get_challenges(challenger, NUM_CHALLENGES);
        uint64[] memory plonk_gammas = challenger_get_challenges(challenger, NUM_CHALLENGES);

        for (uint32 i = 0; i < NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP; i++) {
            challenger_observe_hash(challenger, proof_with_public_inputs.plonk_zs_partial_products_cap[i]);
        }
        uint64[] memory plonk_alphas = challenger_get_challenges(challenger, NUM_CHALLENGES);
        console.log(plonk_betas[0]);
        console.log(plonk_gammas[0]);
        console.log(plonk_alphas[0]);

        for (uint32 i = 0; i < NUM_QUOTIENT_POLYS_CAP; i++) {
            challenger_observe_hash(challenger, proof_with_public_inputs.quotient_polys_cap[i]);
        }
        uint64[2] memory plonk_zeta = get_extension_challenge(challenger);
        console.log(plonk_zeta[0], plonk_zeta[1]);

        for (uint32 i = 0; i < NUM_OPENINGS_CONSTANTS; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_constants[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_SIGMAS; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_plonk_sigmas[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_WIRES; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_wires[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_ZS; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_plonk_zs[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PARTIAL_PRODUCTS; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_partial_products[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_QUOTIENT_POLYS; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_quotient_polys[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_ZS_NEXT; i++) {
            challenger_observe_extension(challenger, proof_with_public_inputs.openings_plonk_zs_next[i]);
        }

        // Fri Challenges
        uint64[2] memory fri_alpha = get_extension_challenge(challenger);
        console.log(fri_alpha[0], fri_alpha[1]);
        uint64[NUM_FRI_COMMIT_ROUND][2] memory fri_betas;
        for (uint32 i = 0; i < NUM_FRI_COMMIT_ROUND; i++) {
            for (uint32 j = 0; j < FRI_COMMIT_MERKLE_CAP_HEIGHT; j++) {
                challenger_observe_hash(challenger, proof_with_public_inputs.fri_commit_phase_merkle_caps[i][j]);
            }
            fri_betas[i] = get_extension_challenge(challenger);
            console.log(fri_betas[i][0], fri_betas[i][1]);
        }

        // uint64 fri_pow_response
        // uint32[] fri_query_indices

        bytes25[SIGMAS_CAP_COUNT] memory sc = get_sigma_cap();
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
