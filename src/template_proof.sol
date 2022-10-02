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
//        bytes8[][] fri_query_init_constants_sigmas_v;
//        bytes25[][] fri_query_init_constants_sigmas_p;
//        bytes8[][] fri_query_init_wires_v;
//        bytes25[][] fri_query_init_wires_p;
//        bytes8[][] fri_query_init_zs_partial_v;
//        bytes25[][] fri_query_init_zs_partial_p;
//        bytes8[][] fri_query_init_quotient_v;
//        bytes25[][] fri_query_init_quotient_p;
//        bytes16[][] fri_query_step0_v;
//        bytes25[][] fri_query_step0_p;
//        bytes16[][] fri_query_step1_v;
//        bytes25[][] fri_query_step1_p;
//
//        bytes16[] fri_final_poly_ext_v;
//        bytes8 fri_pow_witness;
//        bytes8[] public_inputs;
//    }

    function get_openings_constants(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_CONSTANTS_PTR + i * 16:]);
    }
    function get_openings_plonk_sigmas(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_PLONK_SIGMAS_PTR + i * 16:]);
    }
    function get_openings_wires(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_WIRES_PTR + i * 16:]);
    }
    function get_openings_plonk_zs(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_PLONK_ZS_PTR + i * 16:]);
    }
    function get_openings_plonk_zs_next(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_PLONK_ZS_NEXT_PTR + i * 16:]);
    }
    function get_openings_partial_products(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_PARTIAL_PRODUCTS_PTR + i * 16:]);
    }
    function get_openings_quotient_polys(bytes calldata proof, uint32 i) internal pure returns(bytes16) {
        return bytes16(proof[$OPENINGS_QUOTIENT_POLYS_PTR + i * 16:]);
    }
}
