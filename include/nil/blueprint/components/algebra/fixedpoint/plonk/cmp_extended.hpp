#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_EXTENDED_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_EXTENDED_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/cmp.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x, y as fixedpoint numbers with \Delta_x = \Delta_y
            // Output: 6 flags with values \in {0,1} indicating equality, less than, greater than, not equal,
            // greater_equal, and less_equal.

            // Works by decomposing the difference of the inputs using the cmp gadget

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_cmp_extended;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_cmp_extended<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using cmp_component =
                    fix_cmp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                cmp_component cmp;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                cmp_component instantiate_cmp(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = cmp_component::get_witness_columns(m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < 5; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    // we include neq, geq, leq after gt and before s,inv,y0... in the trace
                    for (auto i = 5; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i + 3));
                    }
                    return cmp_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                         m1, m2);
                }

            public:
                const cmp_component &get_cmp_component() const {
                    return cmp;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_cmp_extended::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                                                        // I include the number of witness for cmp before the merge,
                                                        // since merge chooses max and we put everything in one row
                                                        std::shared_ptr<manifest_param>(new manifest_single_value_param(
                                                            3 + cmp_component::get_witness_columns(m1, m2))),
                                                        false)
                                                        .merge_with(cmp_component::get_manifest(m1, m2));
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                using input_type = typename cmp_component::input_type;

                struct result_type {
                    var eq = var(0, 0, false);
                    var lt = var(0, 0, false);
                    var gt = var(0, 0, false);
                    var neq = var(0, 0, false);
                    var leq = var(0, 0, false);
                    var geq = var(0, 0, false);
                    result_type(const fix_cmp_extended &component, std::uint32_t start_row_index) {
                        eq = var(component.W(2), start_row_index, false, var::column_type::witness);
                        lt = var(component.W(3), start_row_index, false, var::column_type::witness);
                        gt = var(component.W(4), start_row_index, false, var::column_type::witness);
                        neq = var(component.W(5), start_row_index, false, var::column_type::witness);
                        leq = var(component.W(6), start_row_index, false, var::column_type::witness);
                        geq = var(component.W(7), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const fix_cmp_extended &component, std::size_t start_row_index) {
                        eq = var(component.W(2), start_row_index, false, var::column_type::witness);
                        lt = var(component.W(3), start_row_index, false, var::column_type::witness);
                        gt = var(component.W(4), start_row_index, false, var::column_type::witness);
                        neq = var(component.W(5), start_row_index, false, var::column_type::witness);
                        leq = var(component.W(6), start_row_index, false, var::column_type::witness);
                        geq = var(component.W(7), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {eq, lt, gt, neq, leq, geq};
                    }
                };

                template<typename ContainerType>
                explicit fix_cmp_extended(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), cmp(instantiate_cmp(m1, m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_cmp_extended(WitnessContainerType witness, ConstantContainerType constant,
                                 PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    cmp(instantiate_cmp(m1, m2)) {};

                fix_cmp_extended(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    cmp(instantiate_cmp(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_cmp_extended =
                fix_cmp_extended<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                 BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {
                const std::size_t j = start_row_index;

                // Take m+1 limbs due to potential overflow
                // We just take cmp and put the additional flags in there
                // | x | y | eq | lt | gt | neq | leq | geq | s | inv | y0 | ...

                auto cmp_comp = component.get_cmp_component();
                auto result = generate_assignments(cmp_comp, assignment, instance_input, start_row_index);

                auto x = var_value(assignment, instance_input.x);
                auto y = var_value(assignment, instance_input.y);

                auto one = BlueprintFieldType::value_type::one();
                assignment.witness(component.W(5), j) = one - var_value(assignment, result.eq);
                assignment.witness(component.W(6), j) = one - var_value(assignment, result.gt);
                assignment.witness(component.W(7), j) = one - var_value(assignment, result.lt);

                return typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::var;

                auto cmp_comp = component.get_cmp_component();
                auto constraints = get_constraints(cmp_comp, bp, assignment, instance_input);

                auto eq = var(component.W(2), 0);
                auto lt = var(component.W(3), 0);
                auto gt = var(component.W(4), 0);
                auto neq = var(component.W(5), 0);
                auto leq = var(component.W(6), 0);
                auto geq = var(component.W(7), 0);

                auto one = BlueprintFieldType::value_type::one();
                auto constraint_1 = eq + neq - one;
                auto constraint_2 = geq + lt - one;
                auto constraint_3 = leq + gt - one;

                constraints.reserve(constraints.size() + 3);
                constraints.push_back(constraint_1);
                constraints.push_back(constraint_2);
                constraints.push_back(constraint_3);

                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                auto cmp_comp = component.get_cmp_component();
                generate_copy_constraints(cmp_comp, bp, assignment, instance_input, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_cmp_extended<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_CMP_EXTENDED_HPP
