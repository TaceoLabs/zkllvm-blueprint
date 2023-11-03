#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/rescale.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x as fixedpoint numbers with \Delta_x
            // Output: y as fixedpoint number with \Delta_y = \Delta_y

            // Works by decomposing to the pre-comma part and, depending on \Delta_x, one or two 16-bit post-comma parts
            // and fusing lookup tables: y = exp(x) = exp(x_pre) * exp(x_post1) * exp(x_post2)
            // followed by a rescale

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_exp;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_exp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            public:
                using rescale_component =
                    fix_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                uint8_t m2;    // Post-comma 16-bit limbs
                rescale_component rescale;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                struct var_positions {
                    CellPosition x, y, x_pre, x_post0, y_pre, y_post0, y_mul, q0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (6 + 2 * m2 col(s), 1 row(s))
                    //
                    //     |                                         witness                                         |
                    //  r\c| 0 | 1 |   2   |    3    | .. | 3 + m2 - 1 | m2 + 3| m2 + 4  | m2+5  | m2+6 | .. | 2*m2+5|
                    // +---+---+---+-------+---------+----+------------+-------+---------+-------+------+----+-------+
                    // | 0 | x | y | x_pre | x_post0 | .. | x_postm2-1 | y_pre | y_post0 | y_mul | q0   | .. | qm2-1 |
                    //
                    // rescale uses
                    //     x = y_mul
                    //     y = y
                    //     q0 = q0

                    auto m2 = this->m2;
                    var_positions pos;
                    pos.x = CellPosition(this->W(0), start_row_index);
                    pos.y = CellPosition(this->W(1), start_row_index);
                    pos.x_pre = CellPosition(this->W(2), start_row_index);
                    pos.x_post0 = CellPosition(this->W(3 + 0 * m2), start_row_index);    // occupies m2 cells
                    pos.y_pre = CellPosition(this->W(3 + 1 * m2), start_row_index);
                    pos.y_post0 = CellPosition(this->W(3 + 1 * m2 + 1), start_row_index);
                    pos.y_mul = CellPosition(this->W(3 + 1 * m2 + 2), start_row_index);
                    pos.q0 = CellPosition(this->W(3 + 1 * m2 + 3 + 0 * m2), start_row_index);    // occupies m2 cells
                    return pos;
                }

            private:
                rescale_component instantiate_rescale() const {
                    auto m2 = this->m2;
                    const auto var_pos = this->get_var_pos(static_cast<int64_t>(0));    // row not required -> 0
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = rescale_component::get_witness_columns(m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    witness_list.push_back(var_pos.y_mul.column());    // y_mul = input
                    witness_list.push_back(var_pos.y.column());        // y = output
                    for (auto i = 0; i < m2; i++) {
                        witness_list.push_back(var_pos.q0.column() + i);
                    }
                    return rescale_component(witness_list, std::array<std::uint32_t, 0>(),
                                             std::array<std::uint32_t, 0>(), m2);
                }

            public:
                const rescale_component &get_rescale_component() const {
                    return rescale;
                }

                uint8_t get_m2() const {
                    BLUEPRINT_RELEASE_ASSERT(m2 == rescale.get_m2());
                    return this->m2;
                }

                uint64_t get_delta() const {
                    return rescale.get_delta();
                }

                static std::size_t get_witness_columns(uint8_t m2) {
                    return 5 + M(m2) + rescale_component::get_witness_columns(m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_exp::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(get_witness_columns(m2))),
                        false);
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

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_exp &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    result_type(const fix_exp &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_exp(ContainerType witness, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m2)), m2(M(m2)), rescale(instantiate_rescale()) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_exp(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m2)),
                    m2(M(m2)), rescale(instantiate_rescale()) {};

                fix_exp(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type>
                            constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m2)),
                    m2(M(m2)), rescale(instantiate_rescale()) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_exp =
                fix_exp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index, bool assert_on_out_of_range = true) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                auto m2 = component.get_m2();

                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(magic(var_pos.x)) = x_val;

                uint64_t x_pre_val, x_post_val;
                bool sign = FixedPointHelper<BlueprintFieldType>::split_exp(x_val, 16 * m2, x_pre_val, x_post_val);

                int32_t table_half = FixedPointTables<BlueprintFieldType>::ExpALen / 2;
                int64_t input_a = sign ? table_half - static_cast<int64_t>(x_pre_val) : table_half + x_pre_val;

                auto exp_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_exp_a_16() :
                                             FixedPointTables<BlueprintFieldType>::get_exp_a_32();
                auto exp_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_exp_b_16() :
                                             FixedPointTables<BlueprintFieldType>::get_exp_b_32();

                auto output_a = exp_a_table[0];
                if (input_a >= 0 && input_a < exp_a_table.size()) {
                    output_a = exp_a_table[input_a];
                    assignment.witness(magic(var_pos.x_pre)) = input_a;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(!assert_on_out_of_range);
                    assignment.witness(magic(var_pos.x_pre)) = 0;
                }
                assignment.witness(magic(var_pos.y_pre)) = output_a;

                if (m2 == 2) {
                    uint32_t input_b = x_post_val >> 16;
                    uint32_t input_c = x_post_val & ((1ULL << 16) - 1);
                    BLUEPRINT_RELEASE_ASSERT(input_b >= 0 && input_b < exp_b_table.size());
                    BLUEPRINT_RELEASE_ASSERT(input_c >= 0 && input_c < exp_b_table.size());
                    auto output_b = exp_b_table[input_b];
                    auto y_mul_val = output_a * output_b;
                    assignment.witness(magic(var_pos.y_mul)) = y_mul_val;
                    assignment.witness(magic(var_pos.x_post0)) = input_b;
                    assignment.witness(magic(var_pos.y_post0)) = output_b;
                    assignment.witness(var_pos.x_post0.column() + 1, var_pos.x_post0.row()) = input_c;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(x_post_val >= 0 && x_post_val < exp_b_table.size());
                    auto output_b = exp_b_table[x_post_val];
                    auto y_mul_val = output_a * output_b;
                    assignment.witness(magic(var_pos.y_mul)) = y_mul_val;
                    assignment.witness(magic(var_pos.x_post0)) = x_post_val;
                    assignment.witness(magic(var_pos.y_post0)) = output_b;
                }

                // Assign rescale
                using var = typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::var;
                typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::rescale_component::input_type
                    rescale_input;
                rescale_input.x = var(magic(var_pos.y_mul));
                auto rescale_comp = component.get_rescale_component();
                generate_assignments(rescale_comp, assignment, rescale_input, start_row_index);

                return typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                uint64_t start_row_index = 0;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::var;
                auto m2 = component.get_m2();
                auto delta = component.get_delta();
                uint32_t table_half = FixedPointTables<BlueprintFieldType>::ExpALen / 2;

                auto x = var(magic(var_pos.x));
                auto x_pre = var(magic(var_pos.x_pre));
                auto y_pre = var(magic(var_pos.y_pre));
                auto x_post0 = var(magic(var_pos.x_post0));
                auto y_post0 = var(magic(var_pos.y_post0));

                auto constraint_1 = delta * (x_pre - table_half) - x;
                auto constraint_2 = nil::crypto3::math::expression(y_pre * y_post0);

                if (m2 == 2) {
                    auto x_post1 = var(var_pos.x_post0.column() + 1, var_pos.x_post0.row());    // tab_c_in
                    constraint_1 += (1ULL << 16) * x_post0 + x_post1;
                } else {
                    constraint_1 += x_post0;
                }
                auto y_mul = var(magic(var_pos.y_mul));
                constraint_2 -= y_mul;

                // Constrain rescale
                typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::rescale_component::input_type
                    rescale_input;
                rescale_input.x = var(magic(var_pos.y_mul));
                auto rescale_comp = component.get_rescale_component();
                auto constraint_3 = get_constraint(rescale_comp, bp, assignment, rescale_input);

                // TACEO_TODO extend for lookup constraint
                return {constraint_1, constraint_2, constraint_3};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::var;
                var x = var(magic(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_exp<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_HPP
