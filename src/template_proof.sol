// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

library ProofLib {
    function get_wires_cap(bytes calldata proof, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[i * 25 :]);
    }

    function get_plonk_zs_partial_products_cap(bytes calldata proof, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$PLONK_ZS_PARTIAL_PRODUCTS_CAP_PTR + i * 25 :]);
    }

    function get_quotient_polys_cap(bytes calldata proof, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$QUOTIENT_POLYS_CAP_PTR + i * 25 :]);
    }

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

    function get_fri_commit_phase_merkle_caps(bytes calldata proof, uint32 i, uint32 j) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_COMMIT_PHASE_MERKLE_CAPS_PTR + i * $FRI_COMMIT_ROUND_SIZE + j * 25 :]);
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

    function get_sigma_cap() internal pure returns (bytes25[] memory) {
        bytes25[] memory sc = new bytes25[]($SIGMA_CAP_COUNT);
        $SET_SIGMA_CAP;
        return sc;
    }

    function verify_merkle_proof_to_cap_init_constants_sigmas(bytes calldata proof, uint32 r, uint32 leaf_index) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_CONSTANTS_SIGMAS_P_PTR,
            $NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_P, leaf_index);
        return hash == get_sigma_cap()[new_leaf_index];
    }

    function get_fri_query_init_wires_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_V_PTR + i * 8 :]);
    }

    function get_fri_query_init_wires_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_wires(bytes calldata proof, uint32 r, uint32 leaf_index) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_WIRES_P_PTR,
            $NUM_FRI_QUERY_INIT_WIRES_P, leaf_index);
        return hash == get_wires_cap(proof, new_leaf_index);
    }

    function get_fri_query_init_zs_partial_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_V_PTR + i * 8 :]);
    }

    function get_fri_query_init_zs_partial_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_zs_partial(bytes calldata proof, uint32 r, uint32 leaf_index) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_ZS_PARTIAL_P_PTR,
            $NUM_FRI_QUERY_INIT_ZS_PARTIAL_P, leaf_index);
        return hash == get_plonk_zs_partial_products_cap(proof, new_leaf_index);
    }

    function get_fri_query_init_quotient_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_V_PTR + i * 8 :]);
    }

    function get_fri_query_init_quotient_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_init_quotient(bytes calldata proof, uint32 r, uint32 leaf_index) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $INIT_QUOTIENT_P_PTR,
            $NUM_FRI_QUERY_INIT_QUOTIENT_P, leaf_index);
        return hash == get_quotient_polys_cap(proof, new_leaf_index);
    }

    function get_fri_query_step0_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_V_PTR + i * 16 :]);
    }

    function get_fri_query_step0_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_step0(bytes calldata proof, uint32 r, uint32 leaf_index) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP0_P_PTR,
            $NUM_FRI_QUERY_STEP0_P, leaf_index);
        return hash == get_fri_commit_phase_merkle_caps(proof, 0, new_leaf_index);
    }

    function get_fri_query_step1_v(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_V_PTR + i * 16 :]);
    }

    function get_fri_query_step1_p(bytes calldata proof, uint32 r, uint32 i) internal pure returns (bytes25) {
        return bytes25(proof[$FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_P_PTR + i * 25 :]);
    }

    function verify_merkle_proof_to_cap_step1(bytes calldata proof, uint32 r, uint32 leaf_index) internal pure returns (bool) {
        bytes25 hash;
        uint32 new_leaf_index;
        (hash, new_leaf_index) = get_fri_merkle_proof_to_cap(proof, $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_V_PTR,
            $FRI_QUERY_ROUND_PTR + $FRI_QUERY_ROUND_SIZE * r + $STEP1_P_PTR,
            $NUM_FRI_QUERY_STEP1_P, leaf_index);
        return hash == get_fri_commit_phase_merkle_caps(proof, 1, new_leaf_index);
    }

    function get_fri_final_poly_ext_v(bytes calldata proof, uint32 i) internal pure returns (bytes16) {
        return bytes16(proof[$FRI_FINAL_POLY_EXT_V_PTR + i * 16 :]);
    }

    function get_fri_pow_witness(bytes calldata proof) internal pure returns (bytes8) {
        return bytes8(proof[$FRI_POW_WITNESS_PTR :]);
    }

    function get_public_input_hash(bytes calldata proof) internal pure returns (bytes8[4] memory res) {
        if ($NUM_PUBLIC_INPUTS > 0) {
            bytes32 h = sha256(proof[$PUBLIC_INPUTS_PTR :]);
            res[0] = bytes8(h);
            res[1] = bytes8(h << 64);
            res[2] = bytes8(h << 128);
            res[3] = bytes8(h << 192);
        }
    }
}
