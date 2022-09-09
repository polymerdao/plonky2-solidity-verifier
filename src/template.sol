// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Import this file to use console.log
import "hardhat/console.sol";
import "./Challenger.sol";
import "./Plonk.sol";
import "./GoldilocksField.sol";
import "./GoldilocksExt.sol";

//TODO: uint64 to bytes8 conversion need to take into account the case n > field_order.
contract Plonky2Verifier {
    using ChallengerLib for ChallengerLib.Challenger;
    using GoldilocksFieldLib for uint64;
    using GoldilocksExtLib for uint64[2];

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
    uint32 constant NUM_GATE_CONSTRAINTS = $NUM_GATE_CONSTRAINTS;
    uint32 constant QUOTIENT_DEGREE_FACTOR = $QUOTIENT_DEGREE_FACTOR;
    uint32 constant NUM_REDUCTION_ARITY_BITS = $NUM_REDUCTION_ARITY_BITS;
    uint32 constant NUM_PUBLIC_INPUTS = $NUM_PUBLIC_INPUTS;

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
        bytes8[] public_inputs;
    }

    struct ProofChallenges {
        uint64[] plonk_betas;
        uint64[] plonk_gammas;
        uint64[] plonk_alphas;
        uint64[2] plonk_zeta;
        uint64[2] fri_alpha;
        uint64[2][NUM_FRI_COMMIT_ROUND] fri_betas;
        uint64 fri_pow_response;
        uint32[NUM_FRI_QUERY_ROUND] fri_query_indices;
    }

    function get_sigma_cap() internal pure returns (bytes25[] memory) {
        bytes25[] memory sc = new bytes25[](SIGMAS_CAP_COUNT);
        $SET_SIGMA_CAP;
        return sc;
    }

    function get_k_is() internal pure returns (uint64[NUM_OPENINGS_PLONK_SIGMAS] memory k_is) {
        $SET_K_IS;
    }

    function get_reduction_arity_bits() internal pure returns (uint32[NUM_REDUCTION_ARITY_BITS] memory bits) {
        $SET_REDUCTION_ARITY_BITS;
    }

    function get_g_by_arity_bits(uint32 arity_bits) internal pure returns (uint64) {
        uint64[3] memory g_arity_bits;
        g_arity_bits[0] = $G_ARITY_BITS_1;
        g_arity_bits[1] = $G_ARITY_BITS_2;
        g_arity_bits[2] = $G_ARITY_BITS_3;
        return g_arity_bits[arity_bits - 1];
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

    function le_bytes8_to_ext(bytes8 input) internal pure returns (uint64[2] memory res) {
        res[0] = reverse(uint64(bytes8(input)));
    }

    function le_bytes16_to_ext(bytes16 input) internal pure returns (uint64[2] memory res) {
        res[1] = reverse(uint64(bytes8(input << 64)));
        res[0] = reverse(uint64(bytes8(input)));
    }

    function get_fri_pow_response(ChallengerLib.Challenger memory challenger, bytes8 pow_witness) internal pure returns (uint64 res) {
        uint64 u1 = challenger.get_challenge();
        uint64 u2 = challenger.get_challenge();
        uint64 u3 = challenger.get_challenge();
        uint64 u4 = challenger.get_challenge();
        uint64 u5 = uint64(pow_witness);

        bytes32 h = keccak256(abi.encodePacked(bytes8(reverse(u1)), bytes8(reverse(u2)), bytes8(reverse(u3)),
            bytes8(reverse(u4)), bytes8(u5)));

        res = reverse(uint64(bytes8(h)));
    }

    function hash_public_inputs(Proof calldata proof) internal pure returns (bytes8[4] memory res) {
        if (proof.public_inputs.length == 0) return res;
        bytes32 h = $HASH_PROOF_PUBLIC_INPUTS;
        res[0] = bytes8(h);
        res[1] = bytes8(h << 64);
        res[2] = bytes8(h << 128);
        res[3] = bytes8(h << 192);
    }

    function get_challenges(Proof calldata proof, ProofChallenges memory challenges) internal pure {
        ChallengerLib.Challenger memory challenger;
        challenger.observe_hash(CIRCUIT_DIGEST);
        bytes8[4] memory input_hash = hash_public_inputs(proof);
        for (uint32 i = 0; i < 4; i++) {
            challenger.observe_element(input_hash[i]);
        }
        for (uint32 i = 0; i < NUM_WIRES_CAP; i++) {
            challenger.observe_hash(proof.wires_cap[i]);
        }
        challenges.plonk_betas = challenger.get_challenges(NUM_CHALLENGES);
        challenges.plonk_gammas = challenger.get_challenges(NUM_CHALLENGES);

        for (uint32 i = 0; i < NUM_PLONK_ZS_PARTIAL_PRODUCTS_CAP; i++) {
            challenger.observe_hash(proof.plonk_zs_partial_products_cap[i]);
        }
        challenges.plonk_alphas = challenger.get_challenges(NUM_CHALLENGES);

        for (uint32 i = 0; i < NUM_QUOTIENT_POLYS_CAP; i++) {
            challenger.observe_hash(proof.quotient_polys_cap[i]);
        }
        challenges.plonk_zeta = challenger.get_extension_challenge();

        for (uint32 i = 0; i < NUM_OPENINGS_CONSTANTS; i++) {
            challenger.observe_extension(proof.openings_constants[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_SIGMAS; i++) {
            challenger.observe_extension(proof.openings_plonk_sigmas[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_WIRES; i++) {
            challenger.observe_extension(proof.openings_wires[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_ZS; i++) {
            challenger.observe_extension(proof.openings_plonk_zs[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PARTIAL_PRODUCTS; i++) {
            challenger.observe_extension(proof.openings_partial_products[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_QUOTIENT_POLYS; i++) {
            challenger.observe_extension(proof.openings_quotient_polys[i]);
        }
        for (uint32 i = 0; i < NUM_OPENINGS_PLONK_ZS_NEXT; i++) {
            challenger.observe_extension(proof.openings_plonk_zs_next[i]);
        }

        // Fri Challenges
        challenges.fri_alpha = challenger.get_extension_challenge();
        for (uint32 i = 0; i < NUM_FRI_COMMIT_ROUND; i++) {
            for (uint32 j = 0; j < FRI_COMMIT_MERKLE_CAP_HEIGHT; j++) {
                challenger.observe_hash(proof.fri_commit_phase_merkle_caps[i][j]);
            }
            challenges.fri_betas[i] = challenger.get_extension_challenge();
        }

        for (uint32 i = 0; i < NUM_FRI_FINAL_POLY_EXT_V; i++) {
            challenger.observe_extension(proof.fri_final_poly_ext_v[i]);
        }

        challenges.fri_pow_response = get_fri_pow_response(challenger, proof.fri_pow_witness);
        uint32 lde_size = uint32(1 << (DEGREE_BITS + FRI_RATE_BITS));
        for (uint32 i = 0; i < NUM_FRI_QUERY_ROUND; i++) {
            uint32 ele = uint32(challenger.get_challenge());
            challenges.fri_query_indices[i] = ele % lde_size;
        }
    }

    uint32 constant NUM_PARTIAL_PRODUCTS_TERMS = NUM_OPENINGS_PLONK_SIGMAS / QUOTIENT_DEGREE_FACTOR + 1;

    struct VanishingTerms {
        uint64[2][NUM_GATE_CONSTRAINTS] constraint_terms;
        uint64[2][NUM_CHALLENGES] vanishing_z_1_terms;
        uint64[2][NUM_PARTIAL_PRODUCTS_TERMS * NUM_CHALLENGES] vanishing_partial_products_terms;
    }

    function eval_vanishing_poly(Proof calldata proof, ProofChallenges memory challenges) internal pure returns (VanishingTerms memory vm) {
        // TODO: implement constraint_terms = evaluate_gate_constraints()

        uint64[2] memory l1_x = PlonkLib.eval_l_1(uint64(1 << DEGREE_BITS), challenges.plonk_zeta);
        for (uint32 i = 0; i < NUM_CHALLENGES; i ++) {
            uint64[2] memory z_x = le_bytes16_to_ext(proof.openings_plonk_zs[i]);
            vm.vanishing_z_1_terms[i] = l1_x.mul(z_x.sub(GoldilocksExtLib.one()));

            uint64[2][NUM_OPENINGS_PLONK_SIGMAS] memory numerator_values;
            uint64[2][NUM_OPENINGS_PLONK_SIGMAS] memory denominator_values;

            uint64[NUM_OPENINGS_PLONK_SIGMAS] memory k_is = get_k_is();
            for (uint32 j = 0; j < NUM_OPENINGS_PLONK_SIGMAS; j++) {
                uint64[2] memory wire_value = le_bytes16_to_ext(proof.openings_wires[j]);
                uint64[2] memory s_id = challenges.plonk_zeta.scalar_mul(k_is[j]);
                numerator_values[j] = wire_value.add(s_id.scalar_mul(challenges.plonk_betas[i]));
                numerator_values[j][0] = numerator_values[j][0].add(challenges.plonk_gammas[i]);

                uint64[2] memory s_sigma = le_bytes16_to_ext(proof.openings_plonk_sigmas[j]);
                denominator_values[j] = wire_value.add(s_sigma.scalar_mul(challenges.plonk_betas[i]));
                denominator_values[j][0] = denominator_values[j][0].add(challenges.plonk_gammas[i]);
            }

            uint64[2][NUM_PARTIAL_PRODUCTS_TERMS + 1] memory accs;
            accs[0] = z_x;
            accs[NUM_OPENINGS_PARTIAL_PRODUCTS / NUM_CHALLENGES + 1] = le_bytes16_to_ext(proof.openings_plonk_zs_next[i]);
            for (uint32 j = 1; j < NUM_OPENINGS_PARTIAL_PRODUCTS / NUM_CHALLENGES + 1; j++) {
                accs[j] = le_bytes16_to_ext(proof.openings_partial_products[i * (NUM_OPENINGS_PARTIAL_PRODUCTS / NUM_CHALLENGES) + j - 1]);
            }

            uint32 pos = 0;
            for (uint32 j = 0; j < NUM_PARTIAL_PRODUCTS_TERMS; j++) {
                uint64[2] memory num_prod = numerator_values[pos];
                uint64[2] memory den_prod = denominator_values[pos++];

                for (uint32 k = 1; k < QUOTIENT_DEGREE_FACTOR && pos < NUM_OPENINGS_PLONK_SIGMAS; k++) {
                    num_prod = num_prod.mul(numerator_values[pos]);
                    den_prod = den_prod.mul(denominator_values[pos++]);
                }
                vm.vanishing_partial_products_terms[NUM_PARTIAL_PRODUCTS_TERMS * i + j] = accs[j].mul(num_prod).sub(accs[j + 1].mul(den_prod));
            }
        }

        return vm;
    }

    function reduce_with_powers(uint64[2][QUOTIENT_DEGREE_FACTOR] memory terms, uint64[2] memory alpha) internal pure returns (uint64[2] memory sum) {
        for (uint32 i = QUOTIENT_DEGREE_FACTOR; i > 0; i--) {
            sum = sum.mul(alpha).add(terms[i - 1]);
        }
        return sum;
    }

    function verify_merkle_proof_to_cap_memory(uint32 leaf_index, bytes8[] calldata leaf_data, uint32 leaf_data_len,
        bytes25[] calldata merkle_proof, uint32 merkle_proof_len,
        bytes25[] memory merkle_caps) internal pure returns (bool) {
        bytes memory m;
        for (uint32 i = 0; i < leaf_data_len; i++) {
            m = bytes.concat(m, leaf_data[i]);
        }
        bytes32 current_digest = keccak256(m);

        for (uint32 i = 0; i < merkle_proof_len; i ++) {
            uint32 bit = leaf_index & 1;
            leaf_index = leaf_index >> 1;
            if (bit == 1) {
                current_digest = keccak256(abi.encodePacked(merkle_proof[i], bytes25(current_digest)));
            } else {
                current_digest = keccak256(abi.encodePacked(bytes25(current_digest), merkle_proof[i]));
            }
        }

        return merkle_caps[leaf_index] == bytes25(current_digest);
    }

    function verify_merkle_proof_to_cap_calldata(uint32 leaf_index, bytes8[] calldata leaf_data, uint32 leaf_data_len,
        bytes25[] calldata merkle_proof, uint32 merkle_proof_len,
        bytes25[] calldata merkle_caps) internal pure returns (bool) {
        bytes memory m;
        for (uint32 i = 0; i < leaf_data_len; i++) {
            m = bytes.concat(m, leaf_data[i]);
        }
        bytes32 current_digest = keccak256(m);

        for (uint32 i = 0; i < merkle_proof_len; i ++) {
            uint32 bit = leaf_index & 1;
            leaf_index = leaf_index >> 1;
            if (bit == 1) {
                current_digest = keccak256(abi.encodePacked(merkle_proof[i], bytes25(current_digest)));
            } else {
                current_digest = keccak256(abi.encodePacked(bytes25(current_digest), merkle_proof[i]));
            }
        }

        return merkle_caps[leaf_index] == bytes25(current_digest);
    }

    function verify_merkle_proof_to_cap_step0(Proof calldata proof, uint32 leaf_index, uint32 round) internal pure returns (bool) {
        bytes memory m;
        for (uint32 i = 0; i < NUM_FRI_QUERY_STEP0_V; i++) {
            m = bytes.concat(m, proof.fri_query_step0_v[round][i]);
        }
        bytes32 current_digest = keccak256(m);

        for (uint32 i = 0; i < NUM_FRI_QUERY_STEP0_P; i ++) {
            uint32 bit = leaf_index & 1;
            leaf_index = leaf_index >> 1;
            if (bit == 1) {
                current_digest = keccak256(abi.encodePacked(proof.fri_query_step0_p[round][i], bytes25(current_digest)));
            } else {
                current_digest = keccak256(abi.encodePacked(bytes25(current_digest), proof.fri_query_step0_p[round][i]));
            }
        }

        return proof.fri_commit_phase_merkle_caps[0][leaf_index] == bytes25(current_digest);
    }

    function verify_merkle_proof_to_cap_step1(Proof calldata proof, uint32 leaf_index, uint32 round) internal pure returns (bool) {
        bytes memory m;
        for (uint32 i = 0; i < NUM_FRI_QUERY_STEP1_V; i++) {
            m = bytes.concat(m, proof.fri_query_step1_v[round][i]);
        }
        bytes32 current_digest = keccak256(m);

        for (uint32 i = 0; i < NUM_FRI_QUERY_STEP1_P; i ++) {
            uint32 bit = leaf_index & 1;
            leaf_index = leaf_index >> 1;
            if (bit == 1) {
                current_digest = keccak256(abi.encodePacked(proof.fri_query_step1_p[round][i], bytes25(current_digest)));
            } else {
                current_digest = keccak256(abi.encodePacked(bytes25(current_digest), proof.fri_query_step1_p[round][i]));
            }
        }

        return proof.fri_commit_phase_merkle_caps[1][leaf_index] == bytes25(current_digest);
    }

    function reverse_bits(uint32 num, uint32 bits) internal pure returns (uint32) {
        uint32 rev_num;
        for (uint32 i = 0; i < bits; i++) {
            rev_num = rev_num | ((num >> i) & 1);
            rev_num = rev_num << 1;
        }
        return rev_num >> 1;
    }

    function reduce1(Proof calldata proof, uint64[2] memory alpha) internal pure returns (uint64[2] memory evals) {
        for (uint32 i = NUM_OPENINGS_QUOTIENT_POLYS; i > 0; i --) {
            evals = le_bytes16_to_ext(proof.openings_quotient_polys[i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_OPENINGS_PARTIAL_PRODUCTS; i > 0; i --) {
            evals = le_bytes16_to_ext(proof.openings_partial_products[i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_OPENINGS_PLONK_ZS; i > 0; i --) {
            evals = le_bytes16_to_ext(proof.openings_plonk_zs[i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_OPENINGS_WIRES; i > 0; i --) {
            evals = le_bytes16_to_ext(proof.openings_wires[i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_OPENINGS_PLONK_SIGMAS; i > 0; i --) {
            evals = le_bytes16_to_ext(proof.openings_plonk_sigmas[i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_OPENINGS_CONSTANTS; i > 0; i --) {
            evals = le_bytes16_to_ext(proof.openings_constants[i - 1]).add(evals.mul(alpha));
        }
    }

    function reduce2(Proof calldata proof, uint32 round, uint64[2] memory alpha) internal pure returns (uint64[2] memory evals) {
        // bool constants_sigmas_blinding = false;
        // bool other_oracles_blinding = $ZERO_KNOWLEDGE;
        for (uint32 i = NUM_FRI_QUERY_INIT_QUOTIENT_V; i > 0; i --) {
            evals = le_bytes8_to_ext(proof.fri_query_init_quotient_v[round][i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_FRI_QUERY_INIT_ZS_PARTIAL_V; i > 0; i --) {
            evals = le_bytes8_to_ext(proof.fri_query_init_zs_partial_v[round][i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_FRI_QUERY_INIT_WIRES_V; i > 0; i --) {
            evals = le_bytes8_to_ext(proof.fri_query_init_wires_v[round][i - 1]).add(evals.mul(alpha));
        }
        for (uint32 i = NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_V; i > 0; i --) {
            evals = le_bytes8_to_ext(proof.fri_query_init_constants_sigmas_v[round][i - 1]).add(evals.mul(alpha));
        }
    }

    function reduce3(Proof calldata proof, uint32 round, uint64[2] memory alpha) internal pure returns (uint64[2] memory evals) {
        for (uint32 i = NUM_CHALLENGES; i > 0; i --) {
            evals = le_bytes8_to_ext(proof.fri_query_init_zs_partial_v[round][i - 1]).add(evals.mul(alpha));
        }
    }

    // TODO: optimization barycentric_weights calculations
    function cal_barycentric_weights(uint64[2][8] memory points, uint32 arity) internal pure returns (uint64[2][8] memory barycentric_weights) {
        barycentric_weights[0][0] = points[0][0].sub(points[1][0]);
        for (uint32 j = 2; j < arity; j++) {
            barycentric_weights[0][0] = barycentric_weights[0][0].mul(points[0][0].sub(points[j][0]));
        }
        for (uint32 j = 1; j < arity; j++) {
            barycentric_weights[j][0] = points[j][0].sub(points[0][0]);
            for (uint32 k = 1; k < arity; k++) {
                if (j != k) {
                    barycentric_weights[j][0] = barycentric_weights[j][0].mul(points[j][0].sub(points[k][0]));
                }
            }
        }
        for (uint32 j = 0; j < arity; j++) {
            barycentric_weights[j][0] = barycentric_weights[j][0].inverse();
        }
        return barycentric_weights;
    }

    function get_points(uint32 arity_bits, uint32 x_index_within_coset, uint64 subgroup_x) internal pure returns (uint64[2][8] memory points) {
        uint32 arity = uint32(1 << arity_bits);
        uint64 g_arity = get_g_by_arity_bits(arity_bits);
        uint32 rev_x_index_within_coset = reverse_bits(x_index_within_coset, arity_bits);
        points[0][0] = subgroup_x.mul(g_arity.exp(arity - rev_x_index_within_coset));
        for (uint32 i = 1; i < arity; i++) {
            points[i][0] = points[i - 1][0].mul(g_arity);
        }
    }

    function compute_evaluation(Proof calldata proof, uint64[2] memory fri_beta, uint32 round, uint32 reduction,
        uint32 arity_bits, uint64[2][8] memory points) internal pure returns (uint64[2] memory){
        uint64[2][8] memory barycentric_weights = cal_barycentric_weights(points, uint32(1 << arity_bits));

        // Interpolate
        // Check if Lagrange formula would divide by zero?
        uint64[2] memory l_x;
        l_x = fri_beta.sub(points[0]);
        for (uint32 i = 1; i < uint32(1 << arity_bits); i++) {
            l_x = l_x.mul(fri_beta.sub(points[i]));
        }
        uint64[2] memory sum;
        for (uint32 i = 0; i < uint32(1 << arity_bits); i++) {
            if (reduction == 0) {
                sum = sum.add(barycentric_weights[i].div(fri_beta.sub(points[i]))
                .mul(le_bytes16_to_ext(proof.fri_query_step0_v[round][reverse_bits(i, arity_bits)])));
            } else {
                sum = sum.add(barycentric_weights[i].div(fri_beta.sub(points[i]))
                .mul(le_bytes16_to_ext(proof.fri_query_step1_v[round][reverse_bits(i, arity_bits)])));
            }
        }
        return l_x.mul(sum);
    }

    function verify_fri_proof(Proof calldata proof, ProofChallenges memory challenges) internal pure returns (bool) {
        // Precomputed reduced openings
        uint64[2][2] memory precomputed_reduced_evals;
        precomputed_reduced_evals[0] = reduce1(proof, challenges.fri_alpha);
        for (uint32 i = NUM_OPENINGS_PLONK_ZS_NEXT; i > 0; i --) {
            precomputed_reduced_evals[1] = le_bytes16_to_ext(proof.openings_plonk_zs_next[i - 1]).add(precomputed_reduced_evals[1].mul(challenges.fri_alpha));
        }
        uint64[2] memory zeta_next;
        {
            uint64[2] memory g;
            g[0] = $G_FROM_DEGREE_BITS_0;
            g[1] = $G_FROM_DEGREE_BITS_1;
            zeta_next = g.mul(challenges.plonk_zeta);
        }
        for (uint32 round = 0; round < NUM_FRI_QUERY_ROUND; round++) {
            if (!verify_merkle_proof_to_cap_memory(challenges.fri_query_indices[round],
                proof.fri_query_init_constants_sigmas_v[round], NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_V,
                proof.fri_query_init_constants_sigmas_p[round], NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_P,
                get_sigma_cap())) {
                return false;
            }

            if (!verify_merkle_proof_to_cap_calldata(challenges.fri_query_indices[round],
                proof.fri_query_init_wires_v[round], NUM_FRI_QUERY_INIT_WIRES_V,
                proof.fri_query_init_wires_p[round], NUM_FRI_QUERY_INIT_WIRES_P,
                proof.wires_cap)) {
                return false;
            }

            if (!verify_merkle_proof_to_cap_calldata(challenges.fri_query_indices[round],
                proof.fri_query_init_zs_partial_v[round], NUM_FRI_QUERY_INIT_ZS_PARTIAL_V,
                proof.fri_query_init_zs_partial_p[round], NUM_FRI_QUERY_INIT_ZS_PARTIAL_P,
                proof.plonk_zs_partial_products_cap)) {
                return false;
            }

            if (!verify_merkle_proof_to_cap_calldata(challenges.fri_query_indices[round],
                proof.fri_query_init_quotient_v[round], NUM_FRI_QUERY_INIT_QUOTIENT_V,
                proof.fri_query_init_quotient_p[round], NUM_FRI_QUERY_INIT_QUOTIENT_P,
                proof.quotient_polys_cap)) {
                return false;
            }

            uint64[2] memory old_eval;
            uint64[2] memory subgroup_x;
            {
                uint64[2] memory sum;
                subgroup_x[0] = GoldilocksFieldLib.mul($MULTIPLICATIVE_GROUP_GENERATOR,
                    GoldilocksFieldLib.exp($PRIMITIVE_ROOT_OF_UNITY_LDE,
                    reverse_bits(challenges.fri_query_indices[round], $LOG_SIZE_OF_LDE_DOMAIN)));

                sum = challenges.fri_alpha.exp(NUM_FRI_QUERY_INIT_CONSTANTS_SIGMAS_V + NUM_FRI_QUERY_INIT_WIRES_V +
                NUM_FRI_QUERY_INIT_ZS_PARTIAL_V + NUM_FRI_QUERY_INIT_ZS_PARTIAL_V).mul(sum);
                sum = sum.add(reduce2(proof, round, challenges.fri_alpha).sub(precomputed_reduced_evals[0])
                .div(subgroup_x.sub(challenges.plonk_zeta)));

                sum = challenges.fri_alpha.exp(NUM_CHALLENGES).mul(sum);
                sum = sum.add(reduce3(proof, round, challenges.fri_alpha).sub(precomputed_reduced_evals[1])
                .div(subgroup_x.sub(zeta_next)));

                old_eval = sum.mul(subgroup_x);
            }
            uint32[NUM_REDUCTION_ARITY_BITS] memory arity_bits = get_reduction_arity_bits();
            for (uint32 i = 0; i < NUM_REDUCTION_ARITY_BITS; i++) {
                uint32 arity = uint32(1 << arity_bits[i]);
                uint32 coset_index = challenges.fri_query_indices[round] >> arity_bits[i];
                uint32 x_index_within_coset = challenges.fri_query_indices[round] & (arity - 1);
                uint64[2] memory eval;
                if (i == 0) {
                    eval = le_bytes16_to_ext(proof.fri_query_step0_v[round][x_index_within_coset]);
                } else {
                    eval = le_bytes16_to_ext(proof.fri_query_step1_v[round][x_index_within_coset]);
                }
                if (!eval.equal(old_eval)) return false;
                uint64[2][8] memory points = get_points(arity_bits[i], x_index_within_coset, subgroup_x[0]);
                old_eval = compute_evaluation(proof, challenges.fri_betas[i], round, i, arity_bits[i], points);

                if (i == 0 && !verify_merkle_proof_to_cap_step0(proof, coset_index, round)) {
                    return false;
                }
                if (i == 1 && !verify_merkle_proof_to_cap_step1(proof, coset_index, round)) {
                    return false;
                }

                // Update the point x to x^arity.
                subgroup_x[0] = subgroup_x[0].exp_power_of_2(arity_bits[i]);
                challenges.fri_query_indices[round] = coset_index;
            }

            // Final check of FRI. After all the reductions, we check that the final polynomial is equal
            // to the one sent by the prover.
            uint64[2] memory final_eval;
            for (uint32 i = NUM_FRI_FINAL_POLY_EXT_V; i > 0; i--) {
                final_eval = le_bytes16_to_ext(proof.fri_final_poly_ext_v[i - 1]).add(final_eval.mul(subgroup_x));
            }
            if (!old_eval.equal(final_eval)) return false;
        }
        return true;
    }

    function leading_zeros(uint64 num) internal pure returns (uint32 res) {
        while (0x8000000000000000 & num != 0x8000000000000000) {
            res++;
            num = num << 1;
        }
        return res;
    }

    function verify(Proof calldata proof_with_public_inputs) public pure returns (bool) {
        require(proof_with_public_inputs.fri_final_poly_ext_v.length == NUM_FRI_FINAL_POLY_EXT_V);

        ProofChallenges memory challenges;
        get_challenges(proof_with_public_inputs, challenges);

        require(leading_zeros(challenges.fri_pow_response) >= $MIN_FRI_POW_RESPONSE);

        VanishingTerms memory vm = eval_vanishing_poly(proof_with_public_inputs, challenges);
        uint64[2][NUM_CHALLENGES] memory zeta;
        for (uint32 i = 0; i < NUM_CHALLENGES; i ++) {
            uint64[2] memory alpha;
            alpha[0] = challenges.plonk_alphas[i];
            for (uint32 j = NUM_GATE_CONSTRAINTS; j > 0; j --) {
                zeta[i] = vm.constraint_terms[j - 1].add(zeta[i].mul(alpha));
            }
            for (uint32 j = NUM_PARTIAL_PRODUCTS_TERMS * NUM_CHALLENGES; j > 0; j --) {
                zeta[i] = vm.vanishing_partial_products_terms[j - 1].add(zeta[i].mul(alpha));
            }
            for (uint32 j = NUM_CHALLENGES; j > 0; j --) {
                zeta[i] = vm.vanishing_z_1_terms[j - 1].add(zeta[i].mul(alpha));
            }
        }
        uint64[2] memory zeta_pow_deg = challenges.plonk_zeta.exp_power_of_2(DEGREE_BITS);
        uint64[2] memory z_h_zeta = zeta_pow_deg.sub(GoldilocksExtLib.one());
        for (uint i = 0; i < NUM_CHALLENGES; i++) {
            uint64[2][QUOTIENT_DEGREE_FACTOR] memory terms;
            for (uint j = 0; j < QUOTIENT_DEGREE_FACTOR; j++) {
                terms[j] = le_bytes16_to_ext(proof_with_public_inputs.openings_quotient_polys[i * QUOTIENT_DEGREE_FACTOR + j]);
            }
            if (!zeta[i].equal(z_h_zeta.mul(reduce_with_powers(terms, zeta_pow_deg)))) return false;
        }

        return verify_fri_proof(proof_with_public_inputs, challenges);
    }
}
