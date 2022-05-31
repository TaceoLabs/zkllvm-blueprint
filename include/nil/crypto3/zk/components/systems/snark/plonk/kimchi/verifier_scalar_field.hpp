//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALAR_FIELD_COMPONENT_15_WIRES_HPP
#define CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALAR_FIELD_COMPONENT_15_WIRES_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/component.hpp>

#include <nil/crypto3/zk/algorithms/generate_circuit.hpp>

#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/oracles_scalar.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/zkpm_evaluate.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/perm_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/generic_scalars.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/constraints/index_terms_scalars.hpp>

#include <nil/crypto3/zk/components/hashes/poseidon/plonk/poseidon_15_wires.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType, 
                    typename KimchiCommitmentParamsType, std::size_t... WireIndexes>
                class kimchi_verifier_scalar_field;

                template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,  
                         typename KimchiCommitmentParamsType, std::size_t W0, std::size_t W1,
                         std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                         std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                         std::size_t W13, std::size_t W14>
                class kimchi_verifier_scalar_field<
                    snark::plonk_constraint_system<typename CurveType::scalar_field_type, ArithmetizationParams>,
                    CurveType, KimchiParamsType, KimchiCommitmentParamsType, 
                    W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    using BlueprintFieldType = typename CurveType::scalar_field_type;

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    
                    using oracles_component = oracles_scalar<ArithmetizationType, CurveType, KimchiParamsType,
                                KimchiCommitmentParamsType, W0, W1, W2, W3, W4, W5,
                                W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using zkpm_evaluate_component = zkpm_evaluate<ArithmetizationType,
                                W0, W1, W2, W3, W4, W5,
                                W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using perm_scalars_component = perm_scalars<ArithmetizationType, KimchiParamsType,
                                W0, W1, W2, W3, W4, W5,
                                W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using generic_scalars_component = generic_scalars<ArithmetizationType, KimchiParamsType,
                                W0, W1, W2, W3, W4, W5,
                                W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using index_terms_scalars_component = index_terms_scalars<ArithmetizationType, KimchiParamsType,
                                W0, W1, W2, W3, W4, W5,
                                W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using poseidon_component = zk::components::poseidon<ArithmetizationType, 
                        BlueprintFieldType, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14>;

                    using proof_binding = typename zk::components::binding<ArithmetizationType,
                        BlueprintFieldType>;

                    using verifier_index_type = kimchi_verifier_index_scalar<CurveType>;
                    using argument_type = typename verifier_index_type::argument_type;

                    constexpr static const std::size_t selector_seed = 0x0f24;
                    
                    constexpr static const std::size_t f_comm_msm_size = 1 
                                + generic_scalars_component::output_size
                                + verifier_index_type::constraints_amount;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        row += oracles_component::rows_amount; 

                        row += zkpm_evaluate_component::rows_amount;

                        row += perm_scalars_component::rows_amount;

                        row += generic_scalars_component::rows_amount;

                        row += sub_component::rows_amount;

                        for(std::size_t i = 0; i < verifier_index_type::constraints_amount; i++) {
                            row += index_terms_scalars_component::rows_amount;
                        }

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        verifier_index_type &verifier_index;
                        kimchi_proof_scalar<CurveType, KimchiParamsType,
                            KimchiCommitmentParamsType::eval_rounds> &proof;
                        typename proof_binding::fq_sponge_output &fq_output;
                    };

                    struct result_type {
                        var output;
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        var max_poly_size = var(0, start_row_index + 3, false, var::column_type::constant);

                        typename oracles_component::params_type oracles_params(
                            params.verifier_index, params.proof, params.fq_output
                        );
                        auto oracles_output = oracles_component::generate_circuit(bp, assignment,
                            oracles_params, row);
                        row += oracles_component::rows_amount; 

                        std::array<var, f_comm_msm_size> f_comm_scalars;
                        std::size_t f_comm_idx = 0;

                        var zkp = zkpm_evaluate_component::generate_circuit(bp, assignment,
                            {params.verifier_index.omega, params.verifier_index.domain_size,
                            oracles_output.oracles.zeta}, row).output;
                        row += zkpm_evaluate_component::rows_amount;

                        std::pair<std::size_t, std::size_t> alpha_idxs = 
                            params.verifier_index.alpha_map[argument_type::Permutation];
                        f_comm_scalars[f_comm_idx] = perm_scalars_component::generate_circuit(bp,
                            assignment, {oracles_output.combined_evals, oracles_output.alpha_powers,
                            alpha_idxs.first,
                            params.fq_output.beta, params.fq_output.gamma,
                            zkp}, row).output;
                        f_comm_idx += 1;
                        row += perm_scalars_component::rows_amount;

                        alpha_idxs = 
                            params.verifier_index.alpha_map[argument_type::Generic];
                        std::array<var, generic_scalars_component::output_size> generic_scalars = 
                            generic_scalars_component::generate_circuit(bp,
                                assignment, {oracles_output.combined_evals, oracles_output.alpha_powers,
                                alpha_idxs.first}, row).output;
                        std::copy(std::begin(generic_scalars), std::end(generic_scalars),
                            std::begin(f_comm_scalars) + f_comm_idx);
                        f_comm_idx += generic_scalars_component::output_size;
                        row += generic_scalars_component::rows_amount;

                        // xi^n - 1
                        var vanishing_eval = zk::components::generate_circuit<sub_component>(bp,
                            assignment, {oracles_output.zeta_pow_n, one}, row
                            ).output;
                        row += sub_component::rows_amount;

                        // TODO: make endo_factor generic for different curves
                        typename BlueprintFieldType::value_type endo_factor =
                            0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        auto mds = poseidon_component::mds_constants();

                        for(std::size_t i = 0; i < verifier_index_type::constraints_amount; i++) {
                            f_comm_scalars[f_comm_idx] = index_terms_scalars_component::generate_circuit(
                                bp, assignment, {params.verifier_index.constraints[i],
                                vanishing_eval, oracles_output.oracles.zeta,
                                oracles_output.combined_evals,
                                oracles_output.oracles.alpha,
                                params.fq_output.beta, params.fq_output.gamma,
                                params.fq_output.joint_combiner,
                                endo_factor,
                                mds}, row
                            ).output;
                            row += index_terms_scalars_component::rows_amount;
                        }

                        return result_type();
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);
                        var domain_size = var(0, start_row_index + 2, false, var::column_type::constant);
                        var max_poly_size = var(0, start_row_index + 3, false, var::column_type::constant);

                        typename oracles_component::params_type oracles_params(
                            params.verifier_index, params.proof, params.fq_output
                        );
                        auto oracles_output = oracles_component::generate_assignments(assignment,
                            oracles_params, row);
                        row += oracles_component::rows_amount; 

                        std::array<var, f_comm_msm_size> f_comm_scalars;
                        std::size_t f_comm_idx = 0;
                        var zkp = zkpm_evaluate_component::generate_assignments(assignment,
                            {params.verifier_index.omega, params.verifier_index.domain_size,
                            oracles_output.oracles.zeta}, row).output;
                        row += zkpm_evaluate_component::rows_amount;

                        std::pair<std::size_t, std::size_t> alpha_idxs = 
                            params.verifier_index.alpha_map[argument_type::Permutation];
                        f_comm_scalars[f_comm_idx] = perm_scalars_component::generate_assignments(
                            assignment, {oracles_output.combined_evals, oracles_output.alpha_powers,
                            alpha_idxs.first,
                            params.fq_output.beta, params.fq_output.gamma,
                            zkp}, row).output;
                        f_comm_idx += 1;
                        row += perm_scalars_component::rows_amount;

                        alpha_idxs = 
                            params.verifier_index.alpha_map[argument_type::Generic];
                        std::array<var, generic_scalars_component::output_size> generic_scalars = 
                            generic_scalars_component::generate_assignments(
                                assignment, {oracles_output.combined_evals, oracles_output.alpha_powers,
                                alpha_idxs.first}, row).output;
                        std::copy(std::begin(generic_scalars), std::end(generic_scalars),
                            std::begin(f_comm_scalars) + f_comm_idx);
                        f_comm_idx += generic_scalars_component::output_size;
                        row += generic_scalars_component::rows_amount;

                        // xi^n - 1
                        var vanishing_eval = sub_component::generate_assignments(
                            assignment, {oracles_output.zeta_pow_n, one}, row
                            ).output;
                        row += sub_component::rows_amount;

                        // TODO: make endo_factor generic for different curves
                        typename BlueprintFieldType::value_type endo_factor =
                            0x12CCCA834ACDBA712CAAD5DC57AAB1B01D1F8BD237AD31491DAD5EBDFDFE4AB9_cppui255;
                        auto mds = poseidon_component::mds_constants();

                        for(std::size_t i = 0; i < verifier_index_type::constraints_amount; i++) {
                            f_comm_scalars[f_comm_idx] = index_terms_scalars_component::generate_assignments(
                                assignment, {params.verifier_index.constraints[i],
                                vanishing_eval, oracles_output.oracles.zeta,
                                oracles_output.combined_evals,
                                oracles_output.oracles.alpha,
                                params.fq_output.beta, params.fq_output.gamma,
                                params.fq_output.joint_combiner,
                                endo_factor,
                                mds}, row
                            ).output;
                            row += index_terms_scalars_component::rows_amount;
                        }

                        return result_type();
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               std::size_t component_start_row = 0) {
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row = 0) {
                        
                    }

                    static void
                        generate_assignments_constant(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            assignment.constant(0)[row] = 0;
                            row++;
                            assignment.constant(0)[row] = 1;
                            row++;

                            assignment.constant(0)[row] = params.verifier_index.domain_size;
                            row++;
                            assignment.constant(0)[row] = KimchiCommitmentParamsType::max_poly_size;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_PLONK_PICKLES_VERIFIER_SCALAR_FIELD_COMPONENT_15_WIRES_HPP
