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
// @file Declaration of interfaces for auxiliary components for the VARIABLE_BASE_MULTIPLICATION component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/variable_base_multiplication_per_bit.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/bool_scalar_multiplication.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/non_native/bit_decomposition.hpp>
#include <nil/blueprint/components/algebra/fields/plonk/bit_shift_constant.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            using detail::bit_shift_mode;

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type,
                     typename NonNativePolicyType>
            class variable_base_multiplication;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            class variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    Ed25519Type,
                    basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                        std::size_t lookup_column_amount,
                                                                        std::size_t bits_amount) {
                        return
                            decomposition_component_type::get_rows_amount(witness_amount, lookup_column_amount,
                                                                          bits_amount) +
                            252 * mul_per_bit_component::get_rows_amount(witness_amount, lookup_column_amount) +
                            bool_scalar_mul_component::get_rows_amount(witness_amount, lookup_column_amount);
                }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = typename component_type::manifest_type;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using mul_per_bit_component = variable_base_multiplication_per_bit<
                    ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                using decomposition_component_type = bit_decomposition<ArithmetizationType>;

                using bool_scalar_mul_component = bool_scalar_multiplication<
                    ArithmetizationType, Ed25519Type, non_native_policy_type>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return variable_base_multiplication::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount,
                                                       std::size_t bits_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(
                            bool_scalar_mul_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(mul_per_bit_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(
                            decomposition_component_type::get_gate_manifest(witness_amount, lookup_column_amount,
                                                                            bits_amount));

                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        false
                    ).merge_with(mul_per_bit_component::get_manifest())
                     .merge_with(decomposition_component_type::get_manifest())
                     .merge_with(bool_scalar_mul_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount,
                                                             std::size_t bits_amount) {
                    return rows_amount_internal(witness_amount, lookup_column_amount, bits_amount);
                }

                // We use bits_amount from decomposition subcomponent to initialize rows_amount
                // CRITICAL: do not move decomposition_subcomponent below rows_amount
                const decomposition_component_type decomposition_subcomponent;
                // CRITICAL: do not move decomposition_subcomponent below rows_amount
                const mul_per_bit_component mul_per_bit_subcomponent;
                const bool_scalar_mul_component bool_scalar_mul_subcomponent;

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), 0, decomposition_subcomponent.bits_amount);
                constexpr static const std::size_t gates_amount = 0;

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                    var k;
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const variable_base_multiplication &component, std::uint32_t start_row_index) {
                        using mul_per_bit_component =
                            components::variable_base_multiplication_per_bit<ArithmetizationType,
                                CurveType, Ed25519Type, non_native_policy_type>;
                        mul_per_bit_component component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

                        auto final_mul_per_bit_res = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(
                            component_instance, start_row_index + component.rows_amount - component.mul_per_bit_subcomponent.rows_amount);


                        output.x = {final_mul_per_bit_res.output.x[0],
                                    final_mul_per_bit_res.output.x[1],
                                    final_mul_per_bit_res.output.x[2],
                                    final_mul_per_bit_res.output.x[3]};
                        output.y = {final_mul_per_bit_res.output.y[0],
                                    final_mul_per_bit_res.output.y[1],
                                    final_mul_per_bit_res.output.y[2],
                                    final_mul_per_bit_res.output.y[3]};
                    }
                };

                template<typename ContainerType>
                variable_base_multiplication(ContainerType witness, std::uint32_t bits_amount, bit_shift_mode mode_) :
                    component_type(witness, {}, {}, get_manifest()),
                    decomposition_subcomponent(witness, bits_amount, bit_composition_mode::MSB),
                    mul_per_bit_subcomponent(witness),
                    bool_scalar_mul_subcomponent(witness) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                variable_base_multiplication(WitnessContainerType witness, ConstantContainerType constant,
                                   PublicInputContainerType public_input, std::uint32_t bits_amount,
                                   bit_shift_mode mode_) :
                    component_type(witness, constant, public_input, get_manifest()),
                    decomposition_subcomponent(witness, constant, public_input,
                                               bits_amount, bit_composition_mode::MSB),
                    mul_per_bit_subcomponent(witness, constant, public_input),
                    bool_scalar_mul_subcomponent(witness, constant, public_input) {};

                variable_base_multiplication(
                    std::initializer_list<typename component_type::witness_container_type::value_type>
                        witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type>
                        constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    std::uint32_t bits_amount = 253, bit_shift_mode mode_ = bit_shift_mode::RIGHT) :
                        component_type(witnesses, constants, public_inputs, get_manifest()),
                        decomposition_subcomponent(witnesses, constants, public_inputs,
                                                   bits_amount, bit_composition_mode::MSB),
                        mul_per_bit_subcomponent(witnesses, constants, public_inputs),
                        bool_scalar_mul_subcomponent(witnesses, constants, public_inputs) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            using plonk_ed25519_var_base_mul = variable_base_multiplication<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                typename crypto3::algebra::curves::ed25519,
                basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_assignments(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using component_type =
                        plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>;
                    using non_native_policy_type = typename component_type::non_native_policy_type;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::var;
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;



                    using mul_per_bit_component = typename component_type::mul_per_bit_component;
                    using decomposition_component_type = typename component_type::decomposition_component_type;
                    using bool_scalar_mul_component = typename component_type::bool_scalar_mul_component;

                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename decomposition_component_type::result_type bits =
                        generate_assignments(component.decomposition_subcomponent,
                            assignment, {instance_input.k}, row);
                    row += component.decomposition_subcomponent.rows_amount;

                    typename bool_scalar_mul_component::result_type bool_mul_res =
                        generate_assignments(component.bool_scalar_mul_subcomponent, assignment,
                        typename bool_scalar_mul_component::input_type({{T_x, T_y}, bits.output[0]}), row);
                    row += component.bool_scalar_mul_subcomponent.rows_amount;

                    typename mul_per_bit_component::result_type res_per_bit =
                        generate_assignments(component.mul_per_bit_subcomponent, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {bool_mul_res.output.x, bool_mul_res.output.y}, bits.output[1]}),
                        row);
                    row += component.mul_per_bit_subcomponent.rows_amount;

                    for (std::size_t i = 2; i < 253; i++) {
                        res_per_bit = generate_assignments(component.mul_per_bit_subcomponent, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {res_per_bit.output.x, res_per_bit.output.y}, bits.output[i]}), row);
                        row += component.mul_per_bit_subcomponent.rows_amount;
                    }

                    return typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_circuit(
                    const plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using component_type =
                        plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>;
                    using non_native_policy_type = typename component_type::non_native_policy_type;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::var;
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using mul_per_bit_component = typename component_type::mul_per_bit_component;
                    using decomposition_component_type = typename component_type::decomposition_component_type;
                    using bool_scalar_mul_component = typename component_type::bool_scalar_mul_component;


                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;

                    typename decomposition_component_type::result_type bits =
                    generate_circuit(component.decomposition_subcomponent, bp, assignment, {instance_input.k},
                                     row);
                    row += component.decomposition_subcomponent.rows_amount;

                    typename bool_scalar_mul_component::result_type bool_mul_res =
                        generate_circuit(component.bool_scalar_mul_subcomponent, bp, assignment,
                        typename bool_scalar_mul_component::input_type({{T_x, T_y}, bits.output[0]}), row);
                    row += component.bool_scalar_mul_subcomponent.rows_amount;

                    typename mul_per_bit_component::result_type res_per_bit =
                        generate_circuit(component.mul_per_bit_subcomponent, bp, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {bool_mul_res.output.x, bool_mul_res.output.y}, bits.output[1]}),
                        row);
                    row += component.mul_per_bit_subcomponent.rows_amount;

                    for (std::size_t i = 2; i < 253; i++) {
                        res_per_bit = generate_circuit(component.mul_per_bit_subcomponent, bp, assignment,
                        typename mul_per_bit_component::input_type({{T_x, T_y},
                            {res_per_bit.output.x, res_per_bit.output.y}, bits.output[i]}), row);
                        row += component.mul_per_bit_subcomponent.rows_amount;
                    }

                    return typename plonk_ed25519_var_base_mul<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP