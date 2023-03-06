//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the BATCH_VERIFY_BASE_FIELD component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_BASE_FIELD_HPP
#define CRYPTO3_ZK_BLUEPRINT_BATCH_VERIFY_BASE_FIELD_HPP

#include <nil/crypto3/zk/blueprint/plonk.hpp>
#include <nil/crypto3/zk/assignment/plonk.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/commitment.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/detail/to_group.hpp>
#include <nil/crypto3/zk/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/crypto3/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/types.hpp>
#include <nil/crypto3/zk/components/algebra/curves/pasta/plonk/multi_scalar_mul_15_wires.hpp>

#include <nil/crypto3/algebra/random_element.hpp>
#include <fstream>

namespace nil {
    namespace crypto3 {
        namespace zk {
            namespace components {

                // batched polynomial commitment verification (base field)
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/poly-commitment/src/commitment.rs#L610
                // Input: list of batch evaluation proofs
                //      https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L881-L888
                // Output: -
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                         typename KimchiCommitmentParamsType, std::size_t BatchSize, std::size_t... WireIndexes>
                class batch_verify_base_field;

                template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType,
                         typename KimchiParamsType, typename KimchiCommitmentParamsType, std::size_t BatchSize,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class batch_verify_base_field<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                              CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize, W0,
                                              W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using sub_component = zk::components::subtraction<ArithmetizationType, W0, W1, W2>;

                    using kimchi_constants = zk::components::kimchi_inner_constants<KimchiParamsType>;

                    constexpr static const std::size_t padding_size = kimchi_constants::srs_padding_size();

                    constexpr static const std::size_t final_msm_size = kimchi_constants::final_msm_size(BatchSize);

                    using msm_component =
                        zk::components::element_g1_multi_scalar_mul<ArithmetizationType, CurveType, final_msm_size, W0,
                                                                    W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12,
                                                                    W13, W14>;

                    using to_group_component = zk::components::to_group<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6,
                                                                        W7, W8, W9, W10, W11, W12, W13, W14>;

                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    using opening_proof_type =
                        typename zk::components::kimchi_opening_proof_base<BlueprintFieldType,
                                                                           KimchiCommitmentParamsType::eval_rounds>;

                    using batch_proof_type = typename zk::components::batch_evaluation_proof_base<
                        BlueprintFieldType, ArithmetizationType, KimchiParamsType, KimchiCommitmentParamsType>;

                    using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;

                    using proof_binding =
                        typename zk::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                    using transcript_type = kimchi_transcript_fq<ArithmetizationType, CurveType, W0, W1, W2, W3, W4, W5,
                                                                 W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    constexpr static const std::size_t rows() {
                        std::size_t row = 0;

                        for (std::size_t i = 0; i < BatchSize; i++) {
                            row += transcript_type::absorb_fr_rows;
                            row += transcript_type::challenge_rows;

                            row += to_group_component::rows_amount;
                        }

                        row += msm_component::rows_amount;

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::vector<batch_proof_type> proofs = std::vector<batch_proof_type>(BatchSize);
                        verifier_index_type verifier_index;
                        typename proof_binding::template fr_data<var, BatchSize> fr_output;
                    };

                    struct result_type {
                        var_ec_point output;

                        result_type(std::size_t start_row_index) {
                            output = {
                                var(W4, start_row_index + rows_amount - 1, false),
                                var(W5, start_row_index + rows_amount - 1, false)
                            };
                        }
                    };

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        var two_pow_255(0, start_row_index, false, var::column_type::constant);
                        var zero(0, start_row_index + 1, false, var::column_type::constant);
                        std::vector<var_ec_point> bases;
                        bases.resize(final_msm_size);
                        std::size_t bases_idx = 0;

                        var_ec_point point_at_infinity = {zero, zero};

                        bases[bases_idx++] = params.verifier_index.H;

                        // std::cout << "started wtiting into file" << std::endl;
                        // std::ofstream fout("batch_verify_base_field_hpp.txt");
                        
                        // fout << "bases.X[" << 10 + bases_idx - 1 << "] | H   " << assignment.var_value(params.verifier_index.H.X).data << std::endl;
                        

                        for (std::size_t i = 0; i < KimchiCommitmentParamsType::srs_len; i++) {
                            bases[bases_idx++] = params.verifier_index.G[i];
                        //     fout << "bases.X[" << 10 + bases_idx - 1 << "] | G[i]" << assignment.var_value(params.verifier_index.G[i].X).data << std::endl;
                        }
                        for (std::size_t i = 0; i < padding_size; i++) {
                            bases[bases_idx++] = point_at_infinity;
                        //     fout << "bases.X[" << 10 + bases_idx - 1 << "] |padd?" << assignment.var_value(point_at_infinity.X).data << std::endl;
                        }

                        for (std::size_t i = 0; i < params.proofs.size(); i++) {
                            transcript_type transcript = params.proofs[i].transcript;
                            transcript.absorb_fr_assignment(assignment, {{params.fr_output.cip_shifted[i]}}, row);
                            row += transcript_type::absorb_fr_rows;
                            var t = transcript.challenge_fq_assignment(assignment, row);
                            row += transcript_type::challenge_rows;

                            var_ec_point U = to_group_component::generate_assignments(assignment, 
                                {t}, row).output;
                            row += to_group_component::rows_amount;

                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].o.delta.x,
                            // row); params.proofs[i].transcript.absorb_assignment(assignment,
                            // params.proofs[i].o.delta.y, row);
                            bases[bases_idx++] = params.proofs[i].opening_proof.G;
                            // fout << "bases.X[" << 10 + bases_idx - 1 << "] | op.G" << assignment.var_value(params.proofs[i].opening_proof.G.X).data << std::endl;
                            bases[bases_idx++] = U;
                            // fout << "bases.X[" << 10 + bases_idx - 1 << "] | U   " << assignment.var_value(U.X).data << std::endl;
                            for (std::size_t j = 0; j < params.proofs[i].opening_proof.L.size(); j++) {
                                bases[bases_idx++] = params.proofs[i].opening_proof.L[j];
                            //     fout << "bases.X[" << 10 + bases_idx - 1 << "] | L[i]" << assignment.var_value(params.proofs[i].opening_proof.L[j].X).data << std::endl;
                                bases[bases_idx++] = params.proofs[i].opening_proof.R[j];
                            //     fout << "bases.X[" << 10 + bases_idx - 1 << "] | R[i]" << assignment.var_value(params.proofs[i].opening_proof.R[j].X).data << std::endl;
                            }
                            std::size_t unshifted_size = 0;

                            for (std::size_t j = 0; j < params.proofs[i].comm.size(); j++) {
                                unshifted_size = params.proofs[i].comm[j].parts.size();
                                for (std::size_t k = 0; k < unshifted_size; k++) {
                                    bases[bases_idx++] = params.proofs[i].comm[j].parts[k];
                            //         fout << "bases.X[" << 10 + bases_idx - 1 << "] | comm" << assignment.var_value(params.proofs[i].comm[j].parts[k].X).data << std::endl;
                                }
                            }
                            bases[bases_idx++] = U;
                            // fout << "bases.X[" << 10 + bases_idx - 1 << "] | U   " << assignment.var_value(U.X).data << std::endl;
                            bases[bases_idx++] = params.proofs[i].opening_proof.delta;
                            // fout << "bases.X[" << 10 + bases_idx - 1 << "] | delt" << assignment.var_value(params.proofs[i].opening_proof.delta.X).data << std::endl;
                        }

                        // std::cout << "assert(bases_idx == final_msm_size);" << std::endl;
                        // std::cout << "assert(" << bases_idx << " == " << final_msm_size << ");" << std::endl;

                        // for (std::size_t i = 10; i < final_msm_size + 10; i++) {
                        //     fout << "scalars[" << i << "] |     " << assignment.var_value(params.fr_output.scalars[i - 10]).data << std::endl;
                        // }

                        // fout.close();
                        // std::cout << "writing into the file is finisfed" << std::endl;

                        assert(bases_idx == final_msm_size);

                        typename msm_component::params_type msm_params = {params.fr_output.scalars, bases};
                        auto res = msm_component::generate_assignments(assignment, msm_params, row);
                        row += msm_component::rows_amount;

                        assert(row == start_row_index + rows_amount);
                        return result_type(start_row_index);
                    }

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        std::size_t row = start_row_index;
                        var two_pow_255(0, row, false, var::column_type::constant);
                        var zero(0, start_row_index + 1, false, var::column_type::constant);

                        var_ec_point point_at_infinity = {zero, zero};

                        std::vector<var_ec_point> bases;
                        bases.resize(final_msm_size);
                        std::size_t bases_idx = 0;

                        bases[bases_idx++] = params.verifier_index.H;
                        for (std::size_t i = 0; i < KimchiCommitmentParamsType::srs_len; i++) {
                            bases[bases_idx++] = params.verifier_index.G[i];
                        }
                        for (std::size_t i = 0; i < padding_size; i++) {
                            bases[bases_idx++] = point_at_infinity;
                        }

                        for (std::size_t i = 0; i < params.proofs.size(); i++) {
                            transcript_type transcript = params.proofs[i].transcript;
                            transcript.absorb_fr_circuit(bp, assignment, {{params.fr_output.cip_shifted[i]}}, row);
                            row += transcript_type::absorb_fr_rows;
                            var t = transcript.challenge_fq_circuit(bp, assignment, row);
                            row += transcript_type::challenge_rows;
                            
                            var_ec_point U = to_group_component::generate_circuit(bp, assignment, 
                                {t}, row).output;
                            row += to_group_component::rows_amount;

                            // params.proofs[i].transcript.absorb_assignment(assignment, params.proofs[i].o.delta.x,
                            // row); params.proofs[i].transcript.absorb_assignment(assignment,
                            // params.proofs[i].o.delta.y, row);
                            bases[bases_idx++] = params.proofs[i].opening_proof.G;
                            bases[bases_idx++] = U;
                            for (std::size_t j = 0; j < params.proofs[i].opening_proof.L.size(); j++) {
                                bases[bases_idx++] = params.proofs[i].opening_proof.L[j];
                                bases[bases_idx++] = params.proofs[i].opening_proof.R[j];
                            }
                            std::size_t unshifted_size = 0;

                            for (std::size_t j = 0; j < params.proofs[i].comm.size(); j++) {
                                unshifted_size = params.proofs[i].comm[j].parts.size();
                                for (std::size_t k = 0; k < unshifted_size; k++) {
                                    bases[bases_idx++] = params.proofs[i].comm[j].parts[k];
                                }
                            }
                            bases[bases_idx++] = U;
                            bases[bases_idx++] = params.proofs[i].opening_proof.delta;
                        }

                        assert(bases_idx == final_msm_size);

                        typename msm_component::params_type msm_params = {params.fr_output.scalars, bases};
                        auto res = msm_component::generate_circuit(bp, assignment, msm_params, row);
                        row += msm_component::rows_amount;

                        assert(row == start_row_index + rows_amount);

                        generate_copy_constraints(bp, assignment, params, start_row_index);

                        return result_type(start_row_index);
                    }

                private:

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type params,
                                                  const std::size_t start_row_index) {

                        result_type res = result_type(start_row_index);
                        
                        bp.add_copy_constraint({res.output.X, {0, 1, false, var::column_type::constant}});
                        bp.add_copy_constraint({res.output.Y, {0, 1, false, var::column_type::constant}});
                    }

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::integral_type tmp = 1;
                        assignment.constant(0)[row] = (tmp << 255);
                        row++;
                        assignment.constant(0)[row] = 0;
                    }
                };

            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // CRYPTO3_ZK_BLUEPRINT_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP