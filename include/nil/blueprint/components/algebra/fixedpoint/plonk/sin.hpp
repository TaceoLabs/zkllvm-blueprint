#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SIN_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SIN_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/rem.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by decomposing x into up to three limbs and using the identities sin(a+b) = sin(a)cos(b) +
            // cos(a)sin(b) and cos(a+b) = cos(a)cos(b) - sin(a)sin(b) multiple times, followed by one custom rescale
            // operation. The evaluations of sin and cos are retrieved via pre-computed lookup tables. In case m1 >= 2,
            // a rem operation (mod 2*pi) brings x into a range where one pre-comma limb is sufficient for computing
            // sin(x).

            /**
             * Component representing a sin operation with input x and output y, where y = sin(x).
             *
             * The delta of y is the same as the delta of x.
             *
             * Input:  x ... field element
             * Output: y ... sin(x) (field element)
             * Constant: two_pi ... 2*pi (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_sin;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_sin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                          BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            public:
                using rem_component =
                    fix_rem<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                            BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                uint8_t m1;    // Pre-comma 16-bit limbs
                uint8_t m2;    // Post-comma 16-bit limbs
                rem_component rem;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                struct var_positions {
                    CellPosition x, y, s_x, x0, q0, sin0, cos0, cos1, two_pi;
                    typename rem_component::var_positions rem_pos;
                    int64_t start_row, rem_row, sin_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout (7 + m2 * (2 + m2) col(s), 1 + rem_rows row(s))
                    //              (10 if m2=1, 15 if m2=2 col(s))
                    //
                    // rem only exists if m1=2; rem_rows = 0 if m1=1
                    // two_pi only exists if rem exists
                    // t = 0 if m2 = 1
                    // t = 3 if m2 = 2
                    //
                    //     |                                         witness                                         |
                    //  r\c| 0 | 1 |  2  | 3  | .. | 3+m2|4+m2|..|4+m2+t| 5+m2+t| .. |5+2*m2+t | 6+2*m2+t | 7+2*m2+t |
                    // +---+---+---+-----+----+----+-----+----+--+------+-------+----+---------+----------+----------+
                    // |rem| <rem_witness>                                                                           |
                    // |sin| x | y | s_x | x0 | .. | xm2 | q0 |..|  qt  | sin0  | .. |  sinm2  |   cos0   |   cos1   |
                    //
                    //     | constant |
                    //  r\c|    0     |
                    // +---+----------+
                    // |rem|  two_pi  |

                    auto m1 = this->m1;
                    auto m2 = this->m2;
                    auto t = m2 * m2 - 1;
                    var_positions pos;

                    pos.start_row = start_row_index;
                    pos.rem_row = pos.start_row;
                    pos.sin_row = pos.rem_row;

                    if (m1 == 2) {
                        pos.sin_row += rem.rows_amount;
                        pos.rem_pos = rem.get_var_pos(pos.rem_row);
                        pos.two_pi = CellPosition(this->C(0), pos.rem_row);
                    }

                    pos.x = CellPosition(this->W(0), pos.sin_row);
                    pos.y = CellPosition(this->W(1), pos.sin_row);
                    pos.s_x = CellPosition(this->W(2), pos.sin_row);
                    pos.x0 = CellPosition(this->W(3 + 0 * (m2 + 1)), pos.sin_row);    // occupies m2 + 1 cells
                    pos.q0 = CellPosition(this->W(3 + 1 * (m2 + 1)), pos.sin_row);    // occupies t+1 cells
                    pos.sin0 = CellPosition(this->W(5 + m2 + t), pos.sin_row);        // occupies m2 + 1 cells
                    pos.cos0 = CellPosition(this->W(6 + 2 * m2 + t), pos.sin_row);
                    pos.cos1 = CellPosition(this->W(7 + 2 * m2 + t), pos.sin_row);
                    return pos;
                }

            private:
                rem_component instantiate_rem() const {
                    auto m1 = this->m1;
                    auto m2 = this->m2;
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = rem_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    // if m1=1: a rem_component is constructed but never used.
                    return rem_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                         m1, m2);
                }

            public:
                const rem_component &get_rem_component() const {
                    return rem;
                }

                uint64_t get_delta() const {
                    return 1ULL << (16 * this->m2);
                }

                uint8_t get_m2() const {
                    BLUEPRINT_RELEASE_ASSERT(this->m2 == rem.get_m2());
                    return this->m2;
                }

                uint8_t get_m1() const {
                    return this->m1;
                }

                uint8_t get_m() const {
                    return this->m1 + this->m2;
                }

                constexpr static std::size_t get_witness_columns(uint8_t m2) {
                    return M(m2) == 1 ? 10 : 15;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;

                value_type two_pi;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_sin::gates_amount;
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
                        true);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(uint8_t m1, uint8_t m2) {
                    return M(m1) == 2 ? 1 + rem_component::get_rows_amount(get_witness_columns(m2), 0, m1, m2) : 1;
                }

                constexpr static value_type get_two_pi(uint8_t m2) {
                    return M(m2) == 1 ? value_type(411775ULL) : value_type(26986075409ULL);
                }

                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->m1, this->m2);

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_sin &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    result_type(const fix_sin &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_sin(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m2)), m1(M(m1)), m2(M(m2)), rem(instantiate_rem()),
                    two_pi(get_two_pi(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_sin(WitnessContainerType witness, ConstantContainerType constant,
                        PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m2)),
                    m1(M(m1)), m2(M(m2)), rem(instantiate_rem()), two_pi(get_two_pi(m2)) {};

                fix_sin(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type>
                            public_inputs,
                        uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m2)),
                    m1(M(m1)), m2(M(m2)), rem(instantiate_rem()), two_pi(get_two_pi(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_sin =
                fix_sin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
                using value_type = typename BlueprintFieldType::value_type;

                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto one = value_type::one();
                auto zero = value_type::zero();
                auto delta = value_type(component.get_delta());

                auto x_val = var_value(assignment, instance_input.x);
                assignment.witness(magic(var_pos.x)) = x_val;
                std::vector<uint16_t> x0_val;
                auto x_reduced_val = x_val;    // x_reduced guarantees the use of only one pre-comma limb
                if (m1 == 2) {                 // if two pre-comma limbs are used, x is reduced mod 2*pi
                    assignment.constant(magic(var_pos.two_pi)) = component.two_pi;
                    auto rem_component = component.get_rem_component();
                    typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::rem_component::input_type
                        rem_input;
                    rem_input.x = var(magic(var_pos.x));
                    rem_input.y = var(magic(var_pos.two_pi), true, var::column_type::constant);
                    auto rem_result = generate_assignments(rem_component, assignment, rem_input, var_pos.rem_row);
                    x_reduced_val = var_value(assignment, rem_result.output);
                }
                bool sign = FixedPointHelper<BlueprintFieldType>::decompose(x_reduced_val, x0_val);
                if (m1 == 2) {
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                }
                auto s_x_val = sign ? -one : one;
                BLUEPRINT_RELEASE_ASSERT(x0_val.size() >= (m2 + 1));
                assignment.witness(magic(var_pos.s_x)) = s_x_val;
                for (size_t i = 0; i < m2 + 1; i++) {
                    assignment.witness(var_pos.x0.column() + i, var_pos.x0.row()) = x0_val[i];
                }

                auto sin_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_sin_a_16() :
                                             FixedPointTables<BlueprintFieldType>::get_sin_a_32();
                auto sin_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_sin_b_16() :
                                             FixedPointTables<BlueprintFieldType>::get_sin_b_32();
                auto cos_a_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_cos_a_16() :
                                             FixedPointTables<BlueprintFieldType>::get_cos_a_32();
                auto cos_b_table = m2 == 1 ? FixedPointTables<BlueprintFieldType>::get_cos_b_16() :
                                             FixedPointTables<BlueprintFieldType>::get_cos_b_32();
                auto sin_c_table = FixedPointTables<BlueprintFieldType>::get_sin_c_32();

                auto sin0_val = sin_a_table[x0_val[m2 - 0]];
                auto sin1_val = sin_b_table[x0_val[m2 - 1]];
                auto sin2_val = m2 == 1 ? zero : sin_c_table[x0_val[m2 - 2]];
                auto cos0_val = cos_a_table[x0_val[m2 - 0]];
                auto cos1_val = cos_b_table[x0_val[m2 - 1]];
                auto cos2_val = delta;

                assignment.witness(magic(var_pos.sin0)) = sin0_val;
                assignment.witness(var_pos.sin0.column() + 1, var_pos.sin0.row()) = sin1_val;
                if (m2 == 2) {
                    assignment.witness(var_pos.sin0.column() + 2, var_pos.sin0.row()) = sin2_val;
                }
                assignment.witness(magic(var_pos.cos0)) = cos0_val;
                assignment.witness(magic(var_pos.cos1)) = cos1_val;

                // sin(-a)    = -sin(a)
                // sin(a+b)   = sin(a)cos(b) + cos(a)sin(b)
                // sin(a+b+c) = sin(a+b)cos(c) + cos(a+b)sin(c)
                //            = cos(c) * (sin(a)cos(b) + cos(a)sin(b))
                //            + sin(c) * (cos(a)cos(b) - sin(a)sin(b))
                value_type computation = m2 == 1 ? s_x_val * (sin0_val * cos1_val + cos0_val * sin1_val) :
                                                   s_x_val * (cos2_val * (sin0_val * cos1_val + cos0_val * sin1_val) +
                                                              sin2_val * (cos0_val * cos1_val - sin0_val * sin1_val));

                auto actual_delta = m2 == 1 ? delta : delta * delta;

                auto tmp = FixedPointHelper<BlueprintFieldType>::round_div_mod(computation, actual_delta);
                auto y_val = tmp.quotient;
                auto q_val = tmp.remainder;

                assignment.witness(magic(var_pos.y)) = y_val;

                if (m2 == 1) {
                    assignment.witness(magic(var_pos.q0)) = q_val;
                } else {    // m2 == 2
                    std::vector<uint16_t> q0_val;
                    bool sign_ = FixedPointHelper<BlueprintFieldType>::decompose(q_val, q0_val);
                    BLUEPRINT_RELEASE_ASSERT(!sign_);
                    BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= (4));
                    for (size_t i = 0; i < 4; i++) {
                        assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                    }
                }

                return typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::vector<crypto3::zk::snark::plonk_constraint<BlueprintFieldType>> get_constraints(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);

                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
                auto m1 = component.get_m1();
                auto m2 = component.get_m2();
                auto m = component.get_m();

                auto delta = typename BlueprintFieldType::value_type(component.get_delta());
                auto x = var(magic(var_pos.x));
                auto s_x = var(magic(var_pos.s_x));
                auto x0 = nil::crypto3::math::expression(var(magic(var_pos.x0)));

                // decomposition of x
                for (size_t i = 1; i < m2 + 1; i++) {
                    x0 += var(var_pos.x0.column() + i, var_pos.x0.row()) * (1ULL << (16 * i));
                }
                auto x_reduced = x;
                if (m1 == 2) {
                    typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::rem_component::result_type
                        rem_out(component.get_rem_component(), static_cast<uint32_t>(var_pos.rem_row));
                    x_reduced = var(rem_out.output);
                }
                auto constraint_1 = x_reduced - s_x * x0;

                // sign of x
                auto constraint_2 = (s_x - 1) * (s_x + 1);

                auto y = var(magic(var_pos.y));
                auto sin0 = var(magic(var_pos.sin0));
                auto sin1 = var(var_pos.sin0.column() + 1, var_pos.sin0.row());
                auto cos0 = var(magic(var_pos.cos0));
                auto cos1 = var(magic(var_pos.cos1));
                auto sin2 = var(var_pos.sin0.column() + 2, var_pos.sin0.row());
                auto cos2 = delta;
                auto q = nil::crypto3::math::expression(var(magic(var_pos.q0)));
                for (size_t i = 1; i < m2 * m2; i++) {
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                }

                auto computation = m2 == 1 ?
                                       s_x * (sin0 * cos1 + cos0 * sin1) :
                                       s_x * (cos2 * (sin0 * cos1 + cos0 * sin1) + sin2 * (cos0 * cos1 - sin0 * sin1));
                auto actual_delta = m2 == 1 ? delta : delta * delta;

                auto constraint_3 = 2 * (computation - y * actual_delta - q) + actual_delta;    // "custom" rescale

                // TACEO_TODO extend for lookup constraint for x0, q0, sin0, cos0
                return {constraint_1, constraint_2, constraint_3};
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                auto constraints = get_constraints(component, bp, assignment, instance_input);
                return bp.add_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;
                var x = var(magic(var_pos.x), false);
                bp.add_copy_constraint({instance_input.x, x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                if (component.get_m1() == 2) {    // if m1=2, rem exists
                    typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::rem_component::input_type
                        rem_input;

                    using var = typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::var;

                    rem_input.x = var(magic(var_pos.x), false);
                    rem_input.y = var(magic(var_pos.two_pi), false, var::column_type::constant);

                    generate_circuit(component.get_rem_component(), bp, assignment, rem_input, var_pos.rem_row);
                }

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_sin<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_SIN_HPP