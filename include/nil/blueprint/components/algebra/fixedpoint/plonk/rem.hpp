#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_REM_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_REM_HPP

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

            // Works by proving x = a * y + z  by having 4 decompositions of y, z, a, and d = y - z - 1.

            /**
             * Component representing a modulo operation (division's remainder) with inputs x and y and output z, where
             * z = x mod y. The sign of z and is equal to the sign of y.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same). The delta of z is
             * equal to the deltas of y and z.
             *
             * Input:    x  ... field element
             *           y  ... field element
             * Output:   z  ... x mod y (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_rem;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_rem<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            private:
                uint8_t m1;    // Pre-comma 16-bit limbs
                uint8_t m2;    // Post-comma 16-bit limbs

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                uint8_t get_m() const {
                    return m1 + m2;
                }

                uint8_t get_m1() const {
                    return m1;
                }

                uint8_t get_m2() const {
                    return m2;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_rem::gates_amount;
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
                                          3 + 2 * (M(m2) + M(m1)), 5 + 4 * (m2 + m1), 2 + 2 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (5 + 4 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                /**
                 * Describes the inputs x and y of the fix_rem component.
                 */
                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct FixRemVarPositions {
                    CellPosition x, y, z, s_y, s_a, y0, z0, a0, d0;
                };

                FixRemVarPositions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    FixRemVarPositions pos;
                    switch (this->rows_amount) {
                        case 1:

                            // trace layout (5 + 4*m col(s), 1 row(s))
                            //
                            //  r\c|0|1|2| 3 | 4 | 5 |..| 5+m-1| 5+m|..|5+2m-1|5+2m|..|5+3m-1|5+3m|..|5+4m-1|
                            // +---+-+-+-+---+---+---+--+------+----+--+------+----+--+------+----+--+------+
                            // | 0 |x|y|z|s_y|s_a|y0 |..| ym-1 | z0 |..| zm-1 | a0 |..| am-1 | d_0|..| dm-1 |

                            pos.x = CellPosition(this->W(0), start_row_index);
                            pos.y = CellPosition(this->W(1), start_row_index);
                            pos.z = CellPosition(this->W(2), start_row_index);
                            pos.s_y = CellPosition(this->W(3), start_row_index);
                            pos.s_a = CellPosition(this->W(4), start_row_index);
                            pos.y0 = CellPosition(this->W(5 + 0 * m), start_row_index);    // occupies m cells
                            pos.z0 = CellPosition(this->W(5 + 1 * m), start_row_index);    // occupies m cells
                            pos.a0 = CellPosition(this->W(5 + 2 * m), start_row_index);    // occupies m cells
                            pos.d0 = CellPosition(this->W(5 + 3 * m), start_row_index);    // occupies m cells
                            break;
                        case 2:

                            // trace layout (3 + 2*m col(s), 2 row(s))
                            //
                            //  r\c|  0  |  1  | 2  | 3  | 2+m-1 | 2+m  | 3+m | 2+2m-1 | 3+2m-1   |
                            // +---+-----+-----+----+----+-------+------+-----+--------+----------+
                            // | 0 | s_y | s_a | a0 | .. | am-1  | d_0  | ..  | d_m-1  | <unused> |
                            // | 1 | x   | y   | z  | y0 | ..    | ym-1 | z0  | ..     | zm-1     |

                            pos.s_y = CellPosition(this->W(0), start_row_index);
                            pos.s_a = CellPosition(this->W(1), start_row_index);
                            pos.a0 = CellPosition(this->W(2 + 0 * m), start_row_index);    // occupies m cells
                            pos.d0 = CellPosition(this->W(2 + 1 * m), start_row_index);    // occupies m cells
                            pos.x = CellPosition(this->W(0), start_row_index + 1);
                            pos.y = CellPosition(this->W(1), start_row_index + 1);
                            pos.z = CellPosition(this->W(2), start_row_index + 1);
                            pos.y0 = CellPosition(this->W(3 + 0 * m), start_row_index + 1);    // occupies m cells
                            pos.z0 = CellPosition(this->W(3 + 1 * m), start_row_index + 1);    // occupies m cells
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "rows_amount must be 1 or 2");
                    }
                    return pos;
                }

                /**
                 * Describes the output z of the fix_rem component.
                 */
                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_rem &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.z), false);
                    }

                    result_type(const fix_rem &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.z), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_rem(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_rem(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_rem(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_rem =
                fix_rem<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);

                DivMod<BlueprintFieldType> tmp = FixedPointHelper<BlueprintFieldType>::div_mod(x_val, y_val);
                if (y_val > FixedPointHelper<BlueprintFieldType>::P_HALF && tmp.remainder != 0) {
                    // sign(other.value) == sign(divmod_remainder)
                    tmp.remainder += y_val;
                    tmp.quotient -= 1;
                }
                auto z_val = tmp.remainder;

                assignment.witness(magic(var_pos.x)) = x_val;
                assignment.witness(magic(var_pos.y)) = y_val;
                assignment.witness(magic(var_pos.z)) = z_val;

                std::vector<uint16_t> y0_val;
                std::vector<uint16_t> z0_val;
                std::vector<uint16_t> a0_val;
                std::vector<uint16_t> d0_val;

                constexpr auto one = BlueprintFieldType::value_type::one();

                auto y_abs = y_val;
                bool sign_y = FixedPointHelper<BlueprintFieldType>::abs(y_abs);
                bool sign_y_ = FixedPointHelper<BlueprintFieldType>::decompose(y_abs, y0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_y_);
                auto s_y_val = sign_y ? -one : one;
                assignment.witness(magic(var_pos.s_y)) = s_y_val;

                bool sign_a = FixedPointHelper<BlueprintFieldType>::decompose(tmp.quotient, a0_val);
                auto s_a_val = sign_a ? -one : one;
                assignment.witness(magic(var_pos.s_a)) = s_a_val;

                auto z_abs = z_val;
                bool sign_z = FixedPointHelper<BlueprintFieldType>::abs(z_abs);
                BLUEPRINT_RELEASE_ASSERT((z_abs == 0) || (sign_z == sign_y));
                bool sign_z_ = FixedPointHelper<BlueprintFieldType>::decompose(z_abs, z0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign_z_);

                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(y_abs - z_abs - 1, d0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);

                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                auto m = component.get_m();
                BLUEPRINT_RELEASE_ASSERT(y0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(z0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(d0_val.size() >= m);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.y0.column + i, var_pos.y0.row) = y0_val[i];
                    assignment.witness(var_pos.z0.column + i, var_pos.z0.row) = z0_val[i];
                    assignment.witness(var_pos.a0.column + i, var_pos.a0.row) = a0_val[i];
                    assignment.witness(var_pos.d0.column + i, var_pos.d0.row) = d0_val[i];
                }

                return typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::var;
                auto m = component.get_m();
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                auto y0 = nil::crypto3::math::expression(var(magic(var_pos.y0)));
                auto z0 = nil::crypto3::math::expression(var(magic(var_pos.z0)));
                auto a0 = nil::crypto3::math::expression(var(magic(var_pos.a0)));
                auto d0 = nil::crypto3::math::expression(var(magic(var_pos.d0)));
                for (auto i = 1; i < m; i++) {
                    y0 += var(var_pos.y0.column + i, var_pos.y0.row) * (1ULL << (16 * i));
                    z0 += var(var_pos.z0.column + i, var_pos.z0.row) * (1ULL << (16 * i));
                    a0 += var(var_pos.a0.column + i, var_pos.a0.row) * (1ULL << (16 * i));
                    d0 += var(var_pos.d0.column + i, var_pos.d0.row) * (1ULL << (16 * i));
                }

                auto x = var(magic(var_pos.x));
                auto y = var(magic(var_pos.y));
                auto z = var(magic(var_pos.z));
                auto s_a = var(magic(var_pos.s_a));
                auto s_y = var(magic(var_pos.s_y));

                // TACEO_TODO extend for lookup constraint
                auto constraint_1 = x - s_a * a0 * y - z;
                auto constraint_2 = y - s_y * y0;
                auto constraint_3 = z - s_y * z0;
                auto constraint_4 = y0 - z0 - d0 - 1;
                auto constraint_5 = (s_y - 1) * (s_y + 1);
                auto constraint_6 = (s_a - 1) * (s_a + 1);

                return bp.add_gate(
                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::var;

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                auto x = var(magic(var_pos.x));
                auto y = var(magic(var_pos.y));
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_rem<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_REM_HPP
