// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

// Import this file to use console.log
import "hardhat/console.sol";
import "./Challenger.sol";
import "./Plonk.sol";
import "./GoldilocksField.sol";
import "./GoldilocksExt.sol";

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
        uint64[] plonk_betas;
        uint64[] plonk_gammas;
        uint64[] plonk_alphas;
        uint64[2] plonk_zeta;
        uint64[2] fri_alpha;
        uint64[2][NUM_FRI_COMMIT_ROUND] fri_betas;
        uint64 fri_pow_response;
        uint32[NUM_FRI_QUERY_ROUND] fri_query_indices;
    }

    function get_sigma_cap() internal pure returns (bytes25[SIGMAS_CAP_COUNT] memory sc) {
        $SET_SIGMA_CAP;
    }

    function get_k_is() internal pure returns (uint64[NUM_OPENINGS_PLONK_SIGMAS] memory k_is) {
        $SET_K_IS;
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

        ChallengerLib.Challenger memory new_challenger;
        new_challenger.observe_element(bytes8(reverse(u1)));
        new_challenger.observe_element(bytes8(reverse(u2)));
        new_challenger.observe_element(bytes8(reverse(u3)));
        new_challenger.observe_element(bytes8(reverse(u4)));
        new_challenger.observe_element(bytes8(u5));

        res = new_challenger.get_challenge();
    }

    function get_challenges(Proof calldata proof, ProofChallenges memory challenges) internal pure {
        ChallengerLib.Challenger memory challenger;
        bytes25 input_hash = 0;
        challenger.observe_hash(CIRCUIT_DIGEST);
        challenger.observe_hash(input_hash);
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

    function verify_fri_proof(Proof calldata proof, ProofChallenges memory challenges) internal pure returns (bool) {
        // Precomputed reduced openings
        uint64[2][NUM_CHALLENGES] memory precomputed_reduced_evals;
        for (uint32 i = NUM_OPENINGS_QUOTIENT_POLYS; i > 0; i --) {
            precomputed_reduced_evals[0] = le_bytes16_to_ext(proof.openings_quotient_polys[i - 1]).add(precomputed_reduced_evals[0].mul(challenges.fri_alpha));
        }
        for (uint32 i = NUM_OPENINGS_PARTIAL_PRODUCTS; i > 0; i --) {
            precomputed_reduced_evals[0] = le_bytes16_to_ext(proof.openings_partial_products[i - 1]).add(precomputed_reduced_evals[0].mul(challenges.fri_alpha));
        }
        for (uint32 i = NUM_OPENINGS_PLONK_ZS; i > 0; i --) {
            precomputed_reduced_evals[0] = le_bytes16_to_ext(proof.openings_plonk_zs[i - 1]).add(precomputed_reduced_evals[0].mul(challenges.fri_alpha));
        }
        for (uint32 i = NUM_OPENINGS_WIRES; i > 0; i --) {
            precomputed_reduced_evals[0] = le_bytes16_to_ext(proof.openings_wires[i - 1]).add(precomputed_reduced_evals[0].mul(challenges.fri_alpha));
        }
        for (uint32 i = NUM_OPENINGS_PLONK_SIGMAS; i > 0; i --) {
            precomputed_reduced_evals[0] = le_bytes16_to_ext(proof.openings_plonk_sigmas[i - 1]).add(precomputed_reduced_evals[0].mul(challenges.fri_alpha));
        }
        for (uint32 i = NUM_OPENINGS_CONSTANTS; i > 0; i --) {
            precomputed_reduced_evals[0] = le_bytes16_to_ext(proof.openings_constants[i - 1]).add(precomputed_reduced_evals[0].mul(challenges.fri_alpha));
        }
        for (uint32 i = NUM_OPENINGS_PLONK_ZS_NEXT; i > 0; i --) {
            precomputed_reduced_evals[1] = le_bytes16_to_ext(proof.openings_plonk_zs_next[i - 1]).add(precomputed_reduced_evals[1].mul(challenges.fri_alpha));
        }

        // CONSTANTS_SIGMAS, WIRES, ZS_PARTIAL_PRODUCTS, QUOTIENT
        bool[4] memory oracles_blinding;
        oracles_blinding[1] = true;
        oracles_blinding[2] = true;
        oracles_blinding[3] = true;
        // SIZE_OF_LDE_DOMAIN
        for (uint32 x_index = 0; x_index < NUM_FRI_QUERY_ROUND; x_index ++) {
            // round_proof
            // fri_verify_initial_proof
            // n = SIZE_OF_LDE_DOMAIN
            // instance = ?
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

        // return verify_fri_proof(proof_with_public_inputs, challenges);
        return true;
    }
}
