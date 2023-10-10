#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/type.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x, y as Fixedpoint numbers with \Delta_x = \Delta_y
            // Output: z = Rescale(x * y) with \Delta_z = \Delta_x = \Delta_y

            // Works by proving z = round(x*y/\Delta) via 2xy + \Delta = 2z\Delta + 2q and proving 0 <= q < \Delta via a
            // lookup table

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class mul_rescale;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class mul_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return mul_rescale::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(3)), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const mul_rescale &component, std::uint32_t start_row_index) {
                        output = var(component.W(2), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const mul_rescale &component, std::size_t start_row_index) {
                        output = var(component.W(2), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit mul_rescale(ContainerType witness) : component_type(witness, {}, {}, get_manifest()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                mul_rescale(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input) :
                    component_type(witness, constant, public_input, get_manifest()) {};

                mul_rescale(std::initializer_list<typename component_type::witness_container_type::value_type>
                                witnesses,
                            std::initializer_list<typename component_type::constant_container_type::value_type>
                                constants,
                            std::initializer_list<typename component_type::public_input_container_type::value_type>
                                public_inputs) :
                    component_type(witnesses, constants, public_inputs, get_manifest()) {};
            };
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_mul_rescale =
                mul_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                typename BlueprintFieldType::value_type tmp =
                    var_value(assignment, instance_input.x) * var_value(assignment, instance_input.y);

                DivMod<BlueprintFieldType> res = FixedPoint<BlueprintFieldType>::rescale(tmp);

                // | x | y | z | q |
                assignment.witness(component.W(0), j) = var_value(assignment, instance_input.x);
                assignment.witness(component.W(1), j) = var_value(assignment, instance_input.y);
                assignment.witness(component.W(2), j) = res.quotient;
                assignment.witness(component.W(3), j) = res.remainder;

                return typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::var;
                // 2xy + \Delta = 2z\Delta + 2q and proving
                auto constraint_1 = var(component.W(0), 0) * var(component.W(1), 0) -
                                                       var(component.W(2), 0) * FixedPoint<BlueprintFieldType>::DELTA -
                                                       var(component.W(3), 0)) *
                                                          2 +
                                                      FixedPoint<BlueprintFieldType>::DELTA;

                // TACEO_TODO extend for lookup constraint
                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                var component_y = var(component.W(1), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
                bp.add_copy_constraint({component_y, instance_input.y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_mul_rescale<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_HPP
