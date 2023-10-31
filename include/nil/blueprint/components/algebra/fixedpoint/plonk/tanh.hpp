#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TANH_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TANH_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/range.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Uses the range gadget for clipping the outputs if the inputs are outside [-8, 8], and the exp and
            // positive division gadget

            /**
             * Component representing a tanh operation with input x and output y, where
             * y = tanh(x).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... tanh(x) (field element)
             */

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_tanh;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_tanh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using exp_component =
                    fix_exp<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using range_component =
                    fix_range<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                              BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using div_component = fix_div_by_pos<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                const value_type lo;
                const value_type hi;
                const value_type tanh_min;
                const value_type tanh_max;

                exp_component exp;
                range_component range;
                div_component div;

                static value_type get_hi(uint8_t m2) {
                    return value_type(8) * (1 << (16 * M(m2)));
                }

                static value_type get_lo(uint8_t m2) {
                    return -get_hi(m2);
                }

                static value_type get_tanh_max(uint8_t m2) {
                    return value_type::one() * (1 << (16 * M(m2)));
                }

                static value_type get_tanh_min(uint8_t m2) {
                    return -get_tanh_max(m2);
                }

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                exp_component instantiate_exp(uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = exp_component::get_witness_columns(m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return exp_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                         m2);
                }

                range_component instantiate_range(uint8_t m1, uint8_t m2, const value_type &low,
                                                  const value_type &high) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = range_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return range_component(witness_list, std::array<std::uint32_t, 2>({this->C(0), this->C(1)}),
                                           std::array<std::uint32_t, 0>(), m1, m2, low, high);
                }

                div_component instantiate_div(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = div_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return div_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                         m1, m2);
                }

            public:
                const exp_component &get_exp_component() const {
                    return exp;
                }

                const range_component &get_range_component() const {
                    return range;
                }

                const div_component &get_div_component() const {
                    return div;
                }

                const value_type get_tanh_min() const {
                    return tanh_min;
                }

                const value_type get_tanh_max() const {
                    return tanh_max;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return 4;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest =
                        gate_manifest(gate_manifest_type())
                            .merge_with(exp_component::get_gate_manifest(witness_amount, lookup_column_amount))
                            .merge_with(range_component::get_gate_manifest(witness_amount, lookup_column_amount))
                            .merge_with(div_component::get_gate_manifest(witness_amount, lookup_column_amount));
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(7)), false)
                            .merge_with(exp_component::get_manifest(m2))
                            .merge_with(range_component::get_manifest(m1, m2))
                            .merge_with(div_component::get_manifest(m1, m2));
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    return range_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2) +
                           exp_component::get_rows_amount(witness_amount, lookup_column_amount) +
                           div_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2) + 1;
                }

                const std::size_t rows_amount =
                    get_rows_amount(this->witness_amount(), 0, range.get_m1(), range.get_m2());

                /**
                 * Describes the input x of the fix_tanh component.
                 */
                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct FixTanhVarPositions {
                    CellPosition x, y, exp_x, exp_y, div_x, div_y, div_z, const_min, const_max;
                    int64_t exp_row, div_row, range_row, tanh_row;
                };

                FixTanhVarPositions get_var_pos(const int64_t start_row_index) const {

                    FixTanhVarPositions pos;

                    // trace layout (6+ witness columns, 2 constants columns, 1 row in addition to the rows for the
                    // other gadgets) |   |          witness          |   constant    |
                    //  r\c|0|1|  2  |  3  |  4  |  5  |  6  |   0   |   1   |
                    // +---+-+-+-----+-----+-----+-----+-----+-------+-------+
                    // | 0 | <exp_gadget>                    |       |       |
                    // | r | <div_gadget>                    |       |       |
                    // | s | <range_gadget>                  | <range_const> |
                    // | t |x|y|exp_x|exp_y|div_x|div_y|div_z|  min  |  max  |

                    int64_t row_index = start_row_index + this->rows_amount - 1;

                    pos.x = CellPosition(this->W(0), row_index);
                    pos.y = CellPosition(this->W(1), row_index);
                    pos.exp_x = CellPosition(this->W(2), row_index);
                    pos.exp_y = CellPosition(this->W(3), row_index);
                    pos.div_x = CellPosition(this->W(4), row_index);
                    pos.div_y = CellPosition(this->W(5), row_index);
                    pos.div_z = CellPosition(this->W(6), row_index);

                    pos.const_min = CellPosition(this->C(0), row_index);
                    pos.const_max = CellPosition(this->C(1), row_index);

                    pos.exp_row = start_row_index;
                    pos.div_row = pos.exp_row + exp.rows_amount;
                    pos.range_row = pos.div_row + div.rows_amount;
                    pos.tanh_row = pos.range_row + range.rows_amount;

                    return pos;
                }

                /**
                 * Describes the output y of the fix_tanh component.
                 */
                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_tanh &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    result_type(const fix_tanh &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_tanh(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    lo(get_lo(m2)), hi(get_hi(m2)), tanh_min(get_tanh_min(m2)), tanh_max(get_tanh_max(m2)),
                    exp(instantiate_exp(m2)), range(instantiate_range(m1, m2, lo, hi)), div(instantiate_div(m1, m2)) {};

                fix_tanh(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    lo(get_lo(m2)), hi(get_hi(m2)), tanh_min(get_tanh_min(m2)), tanh_max(get_tanh_max(m2)),
                    exp(instantiate_exp(m2)), range(instantiate_range(m1, m2, lo, hi)), div(instantiate_div(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_tanh =
                fix_tanh<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                using var = typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto range_comp = component.get_range_component();
                auto exp_comp = component.get_exp_component();
                auto div_comp = component.get_div_component();

                auto exp_row = var_pos.exp_row;
                auto div_row = var_pos.div_row;
                auto range_row = var_pos.range_row;
                auto tanh_row = var_pos.tanh_row;

                // Exp input
                typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::exp_component::input_type
                    exp_input;
                exp_input.x = var(magic(var_pos.exp_x));

                // Div input
                typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::div_component::input_type
                    div_input;
                div_input.x = var(magic(var_pos.div_x));
                div_input.y = var(magic(var_pos.div_y));

                // Range input
                typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::range_component::input_type
                    range_input;
                range_input.x = instance_input.x;

                ////////////////////////////////////////////////////////
                // Build the trace
                ////////////////////////////////////////////////////////
                auto x_val = var_value(assignment, instance_input.x);

                // Assign range gadget
                assignment.witness(magic(var_pos.x)) = x_val;

                auto range_out = generate_assignments(range_comp, assignment, range_input, range_row);

                auto in = var_value(assignment, range_out.in);
                auto lt = var_value(assignment, range_out.lt);
                auto gt = var_value(assignment, range_out.gt);

                // Assign exp gadget
                auto x_2 = x_val * 2 * in;
                assignment.witness(magic(var_pos.exp_x)) = x_2;

                auto exp_out = generate_assignments(exp_comp, assignment, exp_input, exp_row);

                auto exp_y = var_value(assignment, exp_out.output);
                assignment.witness(magic(var_pos.exp_y)) = exp_y;

                // Assign div gadget
                auto one = typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::value_type(
                    1 << (16 * range_comp.get_m2()));
                auto div_x = exp_y - one;
                auto div_y = exp_y + one;
                assignment.witness(magic(var_pos.div_x)) = div_x;
                assignment.witness(magic(var_pos.div_y)) = div_y;

                auto div_out = generate_assignments(div_comp, assignment, div_input, div_row);

                auto div_z = var_value(assignment, div_out.output);
                assignment.witness(magic(var_pos.div_z)) = div_z;

                auto y = div_z * in + component.get_tanh_min() * lt + component.get_tanh_max() * gt;
                assignment.witness(magic(var_pos.y)) = y;

                return typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                using var = typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::var;

                const int64_t start_row_index = (int64_t)1 - component.rows_amount;
                const auto var_pos = component.get_var_pos(start_row_index);

                // range output
                auto range_comp = component.get_range_component();
                auto range_res = typename plonk_fixedpoint_tanh<
                    BlueprintFieldType, ArithmetizationParams>::range_component::result_type(range_comp,
                                                                                             static_cast<std::size_t>(
                                                                                                 var_pos.range_row));

                auto x = var(magic(var_pos.x));
                auto y = var(magic(var_pos.y));
                auto exp_x = var(magic(var_pos.exp_x));
                auto exp_y = var(magic(var_pos.exp_y));
                auto div_x = var(magic(var_pos.div_x));
                auto div_y = var(magic(var_pos.div_y));
                auto div_z = var(magic(var_pos.div_z));

                auto const_min = var(magic(var_pos.const_min), true, var::column_type::constant);
                auto const_max = var(magic(var_pos.const_max), true, var::column_type::constant);

                auto in = range_res.in;
                auto lt = range_res.lt;
                auto gt = range_res.gt;

                auto one = typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::value_type(
                    1 << (16 * range_comp.get_m2()));

                auto constraint_1 = exp_x - x * 2 * in;
                auto constraint_2 = div_x - exp_y + one;
                auto constraint_3 = div_y - exp_y - one;
                auto constraint_4 = div_z * in + const_min * lt + const_max * gt - y;

                return bp.add_gate({constraint_1, constraint_2, constraint_3, constraint_4});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto exp_comp = component.get_exp_component();
                auto div_comp = component.get_div_component();

                std::uint32_t exp_row = var_pos.exp_row;
                std::uint32_t div_row = var_pos.div_row;

                auto exp_res =
                    typename plonk_fixedpoint_tanh<BlueprintFieldType,
                                                   ArithmetizationParams>::exp_component::result_type(exp_comp,
                                                                                                      exp_row);

                auto div_res =
                    typename plonk_fixedpoint_tanh<BlueprintFieldType,
                                                   ArithmetizationParams>::div_component::result_type(div_comp,
                                                                                                      div_row);

                auto x = var(magic(var_pos.x));
                auto exp_y = var(magic(var_pos.exp_y));
                auto div_z = var(magic(var_pos.div_z));

                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({exp_res.output, exp_y});
                bp.add_copy_constraint({div_res.output, div_z});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto range_comp = component.get_range_component();
                auto exp_comp = component.get_exp_component();
                auto div_comp = component.get_div_component();

                auto exp_row = var_pos.exp_row;
                auto div_row = var_pos.div_row;
                auto range_row = var_pos.range_row;
                auto tanh_row = var_pos.tanh_row;

                // Exp input
                typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::exp_component::input_type
                    exp_input;
                exp_input.x = var(magic(var_pos.exp_x));

                // Div input
                typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::div_component::input_type
                    div_input;
                div_input.x = var(magic(var_pos.div_x));
                div_input.y = var(magic(var_pos.div_y));

                // Range input
                typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::range_component::input_type
                    range_input;
                range_input.x = instance_input.x;

                // Enable the exp component
                std::size_t exp_selector = generate_gates(exp_comp, bp, assignment, exp_input);
                assignment.enable_selector(exp_selector, exp_row + exp_comp.rows_amount - 1);
                generate_copy_constraints(exp_comp, bp, assignment, exp_input, exp_row);

                // Enable the div component
                std::size_t div_selector = generate_gates(div_comp, bp, assignment, div_input);
                assignment.enable_selector(div_selector, div_row + div_comp.rows_amount - 1);
                generate_copy_constraints(div_comp, bp, assignment, div_input, div_row);

                // Enable the range component
                std::size_t range_selector = generate_gates(range_comp, bp, assignment, range_input);
                assignment.enable_selector(range_selector, range_row + range_comp.rows_amount - 1);
                generate_copy_constraints(range_comp, bp, assignment, range_input, range_row);
                generate_assignments_constant(range_comp, assignment, range_input, range_row);

                // Enable the tanh component
                std::size_t tanh_selector = generate_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(tanh_selector, tanh_row);
                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tanh<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                assignment.constant(magic(var_pos.const_min)) = component.get_tanh_min();
                assignment.constant(magic(var_pos.const_max)) = component.get_tanh_max();
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TANH_HPP
