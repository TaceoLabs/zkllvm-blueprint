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
// @file Declaration of interfaces for auxiliary components for the MERKLE_TREE component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP
#define CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_PER_BIT_EDWARD25519_HPP

#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/doubling.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/complete_addition.hpp>
#include <nil/blueprint/components/algebra/curves/edwards/plonk/non_native/bool_scalar_multiplication.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename ArithmetizationType, typename CurveType, typename Ed25519Type,
                    typename NonNativePolicyType>
            class variable_base_multiplication_per_bit;

            template<typename BlueprintFieldType,
                     typename ArithmetizationParams, typename CurveType, typename Ed25519Type>
            class variable_base_multiplication_per_bit<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    Ed25519Type,
                    basic_non_native_policy<BlueprintFieldType>>:
                public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

                constexpr static const std::size_t rows_amount_internal(std::size_t witness_amount,
                                                                        std::size_t lookup_column_amount) {
                    return
                        doubling_component::get_rows_amount(witness_amount, lookup_column_amount) +
                        complete_addition_component::get_rows_amount(witness_amount, lookup_column_amount) +
                        bool_scalar_multiplication_component::get_rows_amount(witness_amount, lookup_column_amount);

                }

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using manifest_type = typename component_type::manifest_type;
                using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;

                typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using doubling_component = doubling<
                    ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                using complete_addition_component = complete_addition<
                    ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                using bool_scalar_multiplication_component = bool_scalar_multiplication<
                    ArithmetizationType, Ed25519Type, non_native_policy_type>;

                using non_native_range_component = components::range<
                    ArithmetizationType, typename Ed25519Type::base_field_type, non_native_policy_type>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return variable_base_multiplication_per_bit::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount,
                                                       std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                        .merge_with(
                            non_native_range_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(doubling_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(
                            complete_addition_component::get_gate_manifest(witness_amount, lookup_column_amount))
                        .merge_with(
                            bool_scalar_multiplication_component::get_gate_manifest(witness_amount,
                                                                                    lookup_column_amount));

                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(9)),
                        false
                    ).merge_with(non_native_range_component::get_manifest())
                     .merge_with(doubling_component::get_manifest())
                     .merge_with(complete_addition_component::get_manifest())
                     .merge_with(bool_scalar_multiplication_component::get_manifest());
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return rows_amount_internal(witness_amount, lookup_column_amount);
                }

                const std::size_t rows_amount = rows_amount_internal(this->witness_amount(), 0);
                constexpr static const std::size_t gates_amount = 0;

                struct input_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };

                    var_ec_point T;
                    var_ec_point R;
                    var k;
                };

                struct result_type {
                    struct var_ec_point {
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type x;
                        typename non_native_policy_type::template field<typename Ed25519Type::base_field_type>::non_native_var_type y;
                    };
                    var_ec_point output;

                    result_type(const variable_base_multiplication_per_bit &component, std::uint32_t start_row_index) {
                        using complete_addition_component =
                            components::complete_addition<ArithmetizationType, CurveType, Ed25519Type,
                                                          basic_non_native_policy<BlueprintFieldType>>;
                        complete_addition_component component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8}, {0}, {});

                        auto final_addition_res = typename plonk_ed25519_complete_addition<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(
                            component_instance, start_row_index + component.rows_amount - complete_addition_component::get_rows_amount(component.witness_amount(), 0));

                        output.x = {final_addition_res.output.x[0],
                                    final_addition_res.output.x[1],
                                    final_addition_res.output.x[2],
                                    final_addition_res.output.x[3]};
                        output.y = {final_addition_res.output.y[0],
                                    final_addition_res.output.y[1],
                                    final_addition_res.output.y[2],
                                    final_addition_res.output.y[3]};
                    }
                };

                template<typename ContainerType>
                variable_base_multiplication_per_bit(ContainerType witness) :
                    component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                variable_base_multiplication_per_bit(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                variable_base_multiplication_per_bit(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type>
                             constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            using plonk_ed25519_mul_per_bit = variable_base_multiplication_per_bit<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                CurveType,
                typename crypto3::algebra::curves::ed25519,
                basic_non_native_policy<BlueprintFieldType>>;


            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_assignments(
                    const plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::var;
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using doubling_component = doubling<
                        ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                    using complete_addition_component = complete_addition<
                        ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                    using bool_scalar_multiplication_component = bool_scalar_multiplication<
                        ArithmetizationType, Ed25519Type, non_native_policy_type>;

                    doubling_component doubling_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{component.C(0)},{});

                    complete_addition_component complete_addition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{component.C(0)},{});

                    bool_scalar_multiplication_component bool_scalar_multiplication_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;
                    std::array<var, 4> R_x = instance_input.R.x;
                    std::array<var, 4> R_y = instance_input.R.y;

                    typename bool_scalar_multiplication_component::result_type bool_mul_res =
                        generate_assignments(bool_scalar_multiplication_instance, assignment,
                        typename bool_scalar_multiplication_component::input_type({{T_x, T_y}, instance_input.k}), row);
                    row += bool_scalar_multiplication_instance.rows_amount;

                    typename doubling_component::result_type doubling_res =
                        generate_assignments(doubling_instance, assignment,
                        typename doubling_component::input_type({R_x, R_y}), row);
                    row += doubling_instance.rows_amount;

                    typename complete_addition_component::result_type add_res =
                        generate_assignments(complete_addition_instance, assignment,
                        typename complete_addition_component::input_type(
                            {{doubling_res.output.x, doubling_res.output.y},
                             {bool_mul_res.output.x, bool_mul_res.output.y}}), row);
                    row += complete_addition_instance.rows_amount;

                    return typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);

                }

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename CurveType>
            typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type
                generate_circuit(
                    const plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                    using non_native_policy_type = basic_non_native_policy<BlueprintFieldType>;
                    using var = typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::var;
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using doubling_component = doubling<
                        ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                    using complete_addition_component = complete_addition<
                        ArithmetizationType, CurveType, Ed25519Type, non_native_policy_type>;

                    using bool_scalar_multiplication_component = bool_scalar_multiplication<
                        ArithmetizationType, Ed25519Type, non_native_policy_type>;

                    doubling_component doubling_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{component.C(0)},{});

                    complete_addition_component complete_addition_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{component.C(0)},{});

                    bool_scalar_multiplication_component bool_scalar_multiplication_instance(
                        {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                            component.W(5), component.W(6), component.W(7), component.W(8)},{},{});

                    std::size_t row = start_row_index;
                    std::array<var, 4> T_x = instance_input.T.x;
                    std::array<var, 4> T_y = instance_input.T.y;
                    std::array<var, 4> R_x = instance_input.R.x;
                    std::array<var, 4> R_y = instance_input.R.y;

                    typename bool_scalar_multiplication_component::result_type bool_mul_res =
                        generate_circuit(bool_scalar_multiplication_instance, bp, assignment,
                        typename bool_scalar_multiplication_component::input_type({{T_x, T_y}, instance_input.k}), row);
                    row += bool_scalar_multiplication_instance.rows_amount;

                    typename doubling_component::result_type doubling_res =
                        generate_circuit(doubling_instance, bp, assignment,
                        typename doubling_component::input_type({R_x, R_y}), row);
                    row += doubling_instance.rows_amount;

                    typename complete_addition_component::result_type add_res =
                        generate_circuit(complete_addition_instance, bp, assignment,
                        typename complete_addition_component::input_type(
                            {{doubling_res.output.x, doubling_res.output.y},
                             {bool_mul_res.output.x, bool_mul_res.output.y}}), row);
                    row += complete_addition_instance.rows_amount;

                    return typename plonk_ed25519_mul_per_bit<BlueprintFieldType, ArithmetizationParams, CurveType>::result_type(component, start_row_index);
                }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_COMPONENTS_VARIABLE_BASE_MULTIPLICATION_EDWARD25519_HPP