// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library ProofLib {
    //    struct Proof {
    //        bytes25[] wires_cap;
    //        bytes25[] plonk_zs_partial_products_cap;
    //        bytes25[] quotient_polys_cap;
    //
    //  v      bytes16[] openings_constants;
    //  v      bytes16[] openings_plonk_sigmas;
    //  v      bytes16[] openings_wires;
    //  v      bytes16[] openings_plonk_zs;
    //  v      bytes16[] openings_plonk_zs_next;
    //  v      bytes16[] openings_partial_products;
    //  v      bytes16[] openings_quotient_polys;
    //
    //        bytes25[][] fri_commit_phase_merkle_caps;
    //  v     bytes8[][] fri_query_init_constants_sigmas_v;
    //  v     bytes25[][] fri_query_init_constants_sigmas_p;
    //  v     bytes8[][] fri_query_init_wires_v;
    //  v     bytes25[][] fri_query_init_wires_p;
    //  v     bytes8[][] fri_query_init_zs_partial_v;
    //  v     bytes25[][] fri_query_init_zs_partial_p;
    //  v     bytes8[][] fri_query_init_quotient_v;
    //  v     bytes25[][] fri_query_init_quotient_p;
    //  v     bytes16[][] fri_query_step0_v;
    //  v     bytes25[][] fri_query_step0_p;
    //  v     bytes16[][] fri_query_step1_v;
    //  v     bytes25[][] fri_query_step1_p;
    //
    //        bytes16[] fri_final_poly_ext_v;
    //        bytes8 fri_pow_witness;
    //        bytes8[] public_inputs;
    //    }

    function get_openings_constants(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_CONSTANTS_PTR + i * 16 :]);
    }

    function get_openings_plonk_sigmas(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_PLONK_SIGMAS_PTR + i * 16 :]);
    }

    function get_openings_wires(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_WIRES_PTR + i * 16 :]);
    }

    function get_openings_plonk_zs(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_PLONK_ZS_PTR + i * 16 :]);
    }

    function get_openings_plonk_zs_next(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_PLONK_ZS_NEXT_PTR + i * 16 :]);
    }

    function get_openings_partial_products(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_PARTIAL_PRODUCTS_PTR + i * 16 :]);
    }

    function get_openings_quotient_polys(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$OPENINGS_QUOTIENT_POLYS_PTR + i * 16 :]);
    }

    function get_fri_merkle_proof_to_cap(bytes calldata proof, uint32 v_start, uint32 p_start, uint32 merkle_proof_len,
        uint32 leaf_index) internal pure returns (bytes25, uint32) {
        bytes32 current_digest = keccak256(proof[v_start : p_start]);

        for (uint32 i = 0; i < merkle_proof_len; i ++) {
            uint32 bit = leaf_index & 1;
            leaf_index = leaf_index >> 1;
            if (bit == 1) {
                current_digest = keccak256(abi.encodePacked(bytes25(proof[p_start + i * 25 :]), bytes25(current_digest)));
            } else {
                current_digest = keccak256(abi.encodePacked(bytes25(current_digest), bytes25(proof[p_start + i * 25 :])));
            }
        }

        return (bytes25(current_digest), leaf_index);
    }

    function get_fri_query_init_constants_sigmas_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + i * 8 :]);
    }

    function get_fri_query_init_constants_sigmas_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_CONSTANTS_SIGMAS_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_constants_sigmas(bytes calldata proof, uint32 r, uint32 leaf_index, bytes25[] memory merkle_caps) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_CONSTANTS_SIGMAS_P_PTR,
            $NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_P, leaf_index);
        return hash == merkle_caps[new_leaf_index];
    }

    function get_fri_query_init_wires_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_V_PTR + i * 8 :]);
    }

    function get_fri_query_init_wires_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_wires(bytes calldata proof, uint32 r, uint32 leaf_index, bytes25[] calldata merkle_caps) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_P_PTR,
            $NUM_FRI_QUERY_INIT_WIRES_P, leaf_index);
        return hash == merkle_caps[new_leaf_index];
    }

    function get_fri_query_init_zs_partial_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_V_PTR + i * 8 :]);
    }

    function get_fri_query_init_zs_partial_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_zs_partial(bytes calldata proof, uint32 r, uint32 leaf_index, bytes25[] calldata merkle_caps) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_P_PTR,
            $NUM_FRI_QUERY_INIT_ZS_PARTIAL_P, leaf_index);
        return hash == merkle_caps[new_leaf_index];
    }

    function get_fri_query_init_quotient_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_V_PTR + i * 8 :]);
    }

    function get_fri_query_init_quotient_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_quotient(bytes calldata proof, uint32 r, uint32 leaf_index, bytes25[] calldata merkle_caps) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_P_PTR,
            $NUM_FRI_QUERY_INIT_QUOTIENT_P, leaf_index);
        return hash == merkle_caps[new_leaf_index];
    }

    function get_fri_query_step0_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_V_PTR + i * 16 :]);
    }

    function get_fri_query_step0_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_step0(bytes calldata proof, uint32 r, uint32 leaf_index, bytes25[] calldata merkle_caps) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_P_PTR,
            $NUM_FRI_QUERY_STEP0_P, leaf_index);
        return hash == merkle_caps[new_leaf_index];
    }

    function get_fri_query_step1_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_V_PTR + i * 16 :]);
    }

    function get_fri_query_step1_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_step1(bytes calldata proof, uint32 r, uint32 leaf_index, bytes25[] calldata merkle_caps) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_P_PTR,
            $NUM_FRI_QUERY_STEP1_P, leaf_index);
        return hash == merkle_caps[new_leaf_index];
    }
}
