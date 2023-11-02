#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DOT_RESCALE_1_GATE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DOT_RESCALE_1_GATE_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/rescale.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: vec{x}, vec{y} as fixedpoint numbers with \Delta_x = \Delta_y
            // Output: z = Rescale(sum_i x_i * y_i) with \Delta_z = \Delta_x = \Delta_y

            // Works by proving a dot product in multiple rows, followed by a rescale gadget.
            // Thereby, we have the same gadgets for the first and other rows.

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_dot_rescale_1_gate;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_dot_rescale_1_gate<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using rescale_component =
                    fix_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                uint32_t dots;
                uint32_t dots_per_row;
                rescale_component rescale;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                rescale_component instantiate_rescale(uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = rescale_component::get_witness_columns(m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return rescale_component(witness_list, std::array<std::uint32_t, 0>(),
                                             std::array<std::uint32_t, 0>(), m2);
                }

            public:
                const rescale_component &get_rescale_component() const {
                    return rescale;
                }

                uint32_t get_dots() const {
                    return dots;
                }

                uint32_t get_dots_per_row() const {
                    return dots_per_row;
                }

                std::pair<std::size_t, std::size_t> dot_position(std::size_t start_row_index, std::size_t dot_index,
                                                                 bool is_x) const {
                    std::size_t row = start_row_index + dot_index / dots_per_row;
                    std::size_t column = 2 + 2 * (dot_index % dots_per_row);
                    if (!is_x) {
                        column++;
                    }
                    return {row, column};
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                private:
                    uint32_t dots;
                    uint8_t m2;    // Post-comma 16-bit limbs

                public:
                    gate_manifest_type(uint16_t dots, uint8_t m2) : dots(dots), m2(M(m2)) {
                    }

                    std::uint32_t gates_amount() const override {
                        return 2;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint16_t dots, uint8_t m2) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type(dots, m2))
                            .merge_with(rescale_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                // Hardcoded to max 16 for now
                static manifest_type get_manifest(uint32_t dots, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_range_param(4, 16, 2)), false)
                            .merge_with(rescale_component::get_manifest(m2));
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint32_t dots,
                                                             uint8_t m2) {
                    uint32_t dots_per_row = (witness_amount - 2) / 2;    // -2 for sum and previous sum
                    uint32_t rows = dots / dots_per_row;
                    if (dots % dots_per_row != 0) {
                        rows++;
                    }
                    rows += rescale_component::get_rows_amount(witness_amount, lookup_column_amount);
                    return rows;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, dots, rescale.get_m2());

                struct input_type {
                    std::vector<var> x;
                    std::vector<var> y;
                    var zero = var(0, 0, false);    // for asserting zero for unused constraints

                    std::vector<var> all_vars() const {
                        auto z = x;
                        z.insert(end(z), begin(y), end(y));
                        z.push_back(zero);
                        return z;
                    }
                };

                using result_type = typename rescale_component::result_type;

                template<typename ContainerType>
                explicit fix_dot_rescale_1_gate(ContainerType witness, uint32_t dots, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(dots, m2)), dots(dots),
                    rescale(instantiate_rescale(m2)) {
                    dots_per_row = (this->witness_amount() - 2) / 2;
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_dot_rescale_1_gate(WitnessContainerType witness, ConstantContainerType constant,
                                       PublicInputContainerType public_input, uint32_t dots, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(dots, m2)),
                    dots(dots), rescale(instantiate_rescale(m2)) {
                    dots_per_row = (this->witness_amount() - 2) / 2;
                };

                fix_dot_rescale_1_gate(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint32_t dots, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(dots, m2)),
                    dots(dots), rescale(instantiate_rescale(m2)) {
                    dots_per_row = (this->witness_amount() - 2) / 2;
                };
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_dot_rescale_1_gate = fix_dot_rescale_1_gate<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::var get_copy_var(
                const plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams> &component,
                std::size_t start_row_index, std::size_t dot_index, bool is_x) {
                auto pos = component.dot_position(start_row_index, dot_index, is_x);
                using var =
                    typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::var;
                return var(component.W(pos.second), static_cast<int>(pos.first), false);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_dot_rescale_1_gate<
                        BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                // First row:  | dot0 | 0 | x01 | y01 | ... | x0n | y0n | with dot0 = 0 + sum_i x0i * y0i
                // Second row: | dot1 | dot 0 | x11 | y11 | ... | x1n | y1n | with dot1 = dot0 + sum_i x1i * y1i
                // ...
                // Last row:   | dotm | dot m-1 | x1m | y1m | ... | xnm | ynm | with dotm = dot(m-1) + sum_i xmi * ymi
                // Rescale row: | dotm | z | q0 | ...

                auto rows = component.rows_amount;
                auto dots = component.get_dots();
                auto dots_per_row = component.get_dots_per_row();

                BLUEPRINT_RELEASE_ASSERT(instance_input.x.size() == dots);
                BLUEPRINT_RELEASE_ASSERT(instance_input.y.size() == dots);

                auto sum = BlueprintFieldType::value_type::zero();

                for (auto row = 0; row < rows - 1; row++) {
                    assignment.witness(component.W(1), j + row) = sum;
                    for (auto i = 0; i < dots_per_row; i++) {
                        auto dot = dots_per_row * row + i;
                        auto x = dot < dots ? var_value(assignment, instance_input.x[dot]) :
                                              BlueprintFieldType::value_type::zero();
                        auto y = dot < dots ? var_value(assignment, instance_input.y[dot]) :
                                              BlueprintFieldType::value_type::zero();
                        auto mul = x * y;
                        sum += mul;

                        assignment.witness(component.W(2 * i + 2), j + row) = x;
                        assignment.witness(component.W(2 * i + 3), j + row) = y;
                    }
                    assignment.witness(component.W(0), j + row) = sum;
                }

                // Use rescale component
                using var =
                    typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::var;
                typename plonk_fixedpoint_dot_rescale_1_gate<
                    BlueprintFieldType, ArithmetizationParams>::rescale_component::input_type rescale_input;
                rescale_input.x = var(component.W(0), start_row_index + rows - 2, false, var::column_type::witness);

                auto rescale_comp = component.get_rescale_component();
                return generate_assignments(rescale_comp, assignment, rescale_input, start_row_index + rows - 1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType,
                                                                   ArithmetizationParams>::input_type &instance_input) {

                using var =
                    typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::var;
                // sum = prev_sum + sum_i x_i * y_i

                nil::crypto3::math::expression<var> dot;
                for (auto i = 0; i < component.get_dots_per_row(); i++) {
                    dot += var(component.W(2 * i + 2), 0) * var(component.W(2 * i + 3), 0);
                }

                auto constraint_1 = dot + var(component.W(1), 0) - var(component.W(0), 0);

                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType,
                                                                   ArithmetizationParams>::input_type &instance_input,
                const std::size_t start_row_index) {

                using var =
                    typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                auto rows = component.rows_amount;
                auto dots = component.get_dots();
                auto dots_per_row = component.get_dots_per_row();

                // constraint first dot to zero
                bp.add_copy_constraint({instance_input.zero, var(component.W(1), j, false)});

                for (auto i = 0; i < dots; i++) {
                    var component_x = get_copy_var(component, j, i, true);
                    var component_y = get_copy_var(component, j, i, false);
                    bp.add_copy_constraint({instance_input.x[i], component_x});
                    bp.add_copy_constraint({component_y, instance_input.y[i]});
                }

                // Proof that unused dot-slots are constrained to zero
                auto rem = dots % dots_per_row;
                if (rem != 0) {
                    auto row = j + rows - 2;
                    for (auto i = rem; i < dots_per_row; i++) {
                        var component_x = get_copy_var(component, row, i, true);
                        var component_y = get_copy_var(component, row, i, false);
                        bp.add_copy_constraint({instance_input.zero, component_x});
                        bp.add_copy_constraint({instance_input.zero, component_y});
                    }
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_dot_rescale_1_gate<
                        BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

                std::size_t rows = component.rows_amount;
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(selector_index, start_row_index, start_row_index + rows - 2);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                // Use rescale component
                using var =
                    typename plonk_fixedpoint_dot_rescale_1_gate<BlueprintFieldType, ArithmetizationParams>::var;
                typename plonk_fixedpoint_dot_rescale_1_gate<
                    BlueprintFieldType, ArithmetizationParams>::rescale_component::input_type rescale_input;
                rescale_input.x = var(component.W(0), start_row_index + rows - 2, false, var::column_type::witness);

                auto rescale_comp = component.get_rescale_component();
                return generate_circuit(rescale_comp, bp, assignment, rescale_input, start_row_index + rows - 1);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DOT_RESCALE_1_GATE_HPP
