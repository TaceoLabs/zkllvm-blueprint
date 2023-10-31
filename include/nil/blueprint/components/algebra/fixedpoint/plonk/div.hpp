#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x, y as fixedpoint numbers with \Delta_x = \Delta_y
            // Output: z = round(\Delta_z * x / y) with \Delta_z = \Delta_x = \Delta_y

            // Works by proving z = round(\Delta_z * x / y) via 2x\Delta_z + |y| - c = 2zy + 2q and proving 0 <= q < |y|
            // via multiple decompositions and lookup tables for checking the range of the limbs

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_div;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_div<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using div_by_pos_component = fix_div_by_pos<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                div_by_pos_component div_by_pos;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                div_by_pos_component instantiate_div_by_pos(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns =
                        get_rows_amount(this->witness_amount(), 0, m1, m2) == 1 ? 4 + 2 * (m1 + m2) : 2 * (m1 + m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return div_by_pos_component(witness_list, std::array<std::uint32_t, 0>(),
                                                std::array<std::uint32_t, 0>(), m1, m2);
                }

            public:
                const div_by_pos_component &get_div_by_pos_component() const {
                    return div_by_pos;
                }

                uint8_t get_m() const {
                    return div_by_pos.get_m();
                }

                uint8_t get_m1() const {
                    return div_by_pos.get_m1();
                }

                uint8_t get_m2() const {
                    return div_by_pos.get_m2();
                }

                uint64_t get_delta() const {
                    return div_by_pos.get_delta();
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_div::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(
                                          5 + (M(m2) + M(m1)), 5 + 3 * (m2 + m1), 2 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (5 + 3 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, div_by_pos.get_m1(), div_by_pos.get_m2());

                using input_type = typename div_by_pos_component::input_type;
                using result_type = typename div_by_pos_component::result_type;

                template<typename ContainerType>
                explicit fix_div(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)),
                    div_by_pos(instantiate_div_by_pos(m1, m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_div(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    div_by_pos(instantiate_div_by_pos(m1, m2)) {};

                fix_div(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    div_by_pos(instantiate_div_by_pos(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_div =
                fix_div<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;
                auto m = component.get_m();
                auto y_row = j + component.rows_amount - 1;
                auto y_col = component.rows_amount == 1 ? 5 + 2 * m : 5;

                // if one row:
                // | x | y | z | c | q0 | ... | yq_0 | ... | s_y | y0 | ...
                // else;
                // first row: | q0 | ... | yq_0 | ...
                // second row: | x | y | z | c | s_y | y0 | ...
                // Do with div_by_pos component and add the decomposition of y

                // Assign div_by_pos
                auto div_by_pos_comp = component.get_div_by_pos_component();
                auto result = generate_assignments(div_by_pos_comp, assignment, instance_input, start_row_index);

                auto y = var_value(assignment, instance_input.y);
                std::vector<uint16_t> decomp_y;

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(y, decomp_y);
                assignment.witness(component.W(y_col - 1), y_row) =
                    sign ? -BlueprintFieldType::value_type::one() : BlueprintFieldType::value_type::one();
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(decomp_y.size() >= m);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(component.W(y_col + i), y_row) = decomp_y[i];
                }

                return result;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::var;
                // 2x\Delta_z + |y| - c = 2zy + 2q and proving 0 <= q < |y|
                auto m = component.get_m();
                auto delta = component.get_delta();

                int first_row = 1 - (int)component.rows_amount;
                auto y_start = component.rows_amount == 1 ? 5 + 2 * m : 5;
                auto q_start = component.rows_amount == 1 ? 4 : 0;
                auto yq_start = q_start + m;

                auto y_abs = nil::crypto3::math::expression(var(component.W(y_start), 0));
                auto q = nil::crypto3::math::expression(var(component.W(q_start), first_row));
                auto yq = nil::crypto3::math::expression(var(component.W(yq_start), first_row));
                for (auto i = 1; i < m; i++) {
                    y_abs += var(component.W(y_start + i), 0) * (1ULL << (16 * i));
                    q += var(component.W(q_start + i), first_row) * (1ULL << (16 * i));
                    yq += var(component.W(yq_start + i), first_row) * (1ULL << (16 * i));
                }
                auto y_sign = var(component.W(y_start - 1), 0);
                auto x = var(component.W(0), 0);
                auto y = var(component.W(1), 0);
                auto z = var(component.W(2), 0);
                auto c = var(component.W(3), 0);

                auto constraint_1 = 2 * (x * delta - y * z - q) + y_abs - c;
                auto constraint_2 = (c - 1) * c;
                auto constraint_3 = y_abs - q - yq - 1;
                auto constraint_4 = y - y_sign * y_abs;
                auto constraint_5 = (y_sign - 1) * (y_sign + 1);

                // TACEO_TODO extend for lookup constraint
                // return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4, constraint_5});
                return bp.add_gate({constraint_2, constraint_4, constraint_5});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

                // Enable the copy constraints of div_by_pos
                auto div_by_pos_comp = component.get_div_by_pos_component();
                generate_copy_constraints(div_by_pos_comp, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_div<BlueprintFieldType, ArithmetizationParams>::result_type(
                    div_by_pos_comp, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_HPP
