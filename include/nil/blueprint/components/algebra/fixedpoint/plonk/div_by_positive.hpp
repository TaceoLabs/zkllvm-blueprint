#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_BY_POSITIVE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_BY_POSITIVE_HPP

#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/component.hpp>
#include <nil/blueprint/manifest.hpp>
#include <nil/blueprint/basic_non_native_policy.hpp>

#include "nil/blueprint/components/algebra/fixedpoint/type.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/range.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Works by proving z = round(delta_z * x / y) via 2*x*delta_z + y - c = 2zy + 2q and proving 0 <= q < y
            // via multiple decompositions and lookup tables for checking the range of the limbs

            /**
             * Component representing a division operation with inputs x and y and output z, where
             * z = x / y. The sign of z and is equal to the sign of x. This gadget only works if y is positive.
             *
             * The user needs to ensure that the deltas of x and y match (the scale must be the same). The delta of z is
             * equal to the deltas of y and z.
             *
             * Input:    x  ... field element
             *           y  ... field element
             * Output:   z  ... x / y (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_div_by_pos;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_div_by_pos<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

                uint64_t get_delta() const {
                    return 1ULL << (16 * m2);
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    return get_rows_amount(witness_amount, 0, M(m1), M(m2)) == 1 ? 4 + 2 * (m1 + m2) : 2 * (m1 + m2);
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_div_by_pos::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(
                                          new manifest_range_param(2 * (M(m2) + M(m1)), 4 + 2 * (m2 + m1))),
                                      false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    if (4 + 2 * (M(m2) + M(m1)) <= witness_amount) {
                        return 1;
                    } else {
                        return 2;
                    }
                }

                // Includes the constraints + lookup_gates
                constexpr static const std::size_t gates_amount = 2;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, m1, m2);

                struct input_type {
                    var x = var(0, 0, false);
                    var y = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x, y};
                    }
                };

                struct var_positions {
                    CellPosition x, y, z, c, q0, a0;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    auto m = this->get_m();
                    var_positions pos;
                    switch (this->rows_amount) {
                        case 1:

                            // trace layout (4 + 2*m col(s), 1 row(s))
                            //
                            //  r\c| 0 | 1 | 2 | 3 | 4  | .. | 4 + m-1 | 4 + m | .. | 4 + 2m-1 |
                            // +---+---+---+---+---+----+----+---------+-------+----+----------+
                            // | 0 | x | y | z | c | q0 | .. |  qm-1   |  a0   | .. |   am-1   |
                            pos.x = CellPosition(this->W(0), start_row_index);
                            pos.y = CellPosition(this->W(1), start_row_index);
                            pos.z = CellPosition(this->W(2), start_row_index);
                            pos.c = CellPosition(this->W(3), start_row_index);
                            pos.q0 = CellPosition(this->W(4 + 0 * m), start_row_index);    // occupies m cells
                            pos.a0 = CellPosition(this->W(4 + 1 * m), start_row_index);    // occupies m cells
                            break;
                        case 2:

                            // trace layout (2*m col(s), 2 row(s))
                            // recall that m is at least 2.
                            //
                            //  r\c| 0  | .. | m-1  | m  | .. | 2m-1 |
                            // +---+----+----+------+----+----+------+
                            // | 0 | q0 | .. | qm-1 | a0 | .. | am-1 |
                            pos.q0 = CellPosition(this->W(0 + 0 * m), start_row_index);    // occupies m cells
                            pos.a0 = CellPosition(this->W(0 + 1 * m), start_row_index);    // occupies m cells

                            //  r\c| 0 | 1 | 2 | 3 |
                            // +---+---+---+---+---+
                            // | 1 | x | y | z | c |
                            pos.x = CellPosition(this->W(0), start_row_index + 1);
                            pos.y = CellPosition(this->W(1), start_row_index + 1);
                            pos.z = CellPosition(this->W(2), start_row_index + 1);
                            pos.c = CellPosition(this->W(3), start_row_index + 1);
                            break;
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false && "rows_amount must be 1 or 2");
                    }
                    return pos;
                }

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_div_by_pos &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.z), false);
                    }

                    result_type(const fix_div_by_pos &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(magic(var_pos.z), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {};
                    auto table = std::shared_ptr<lookup_table_definition>(new range_table());
                    result.push_back(table);
                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables[range_table::FULL_TABLE_NAME] = 0;    // REQUIRED_TABLE
                    return lookup_tables;
                }
#endif

                template<typename ContainerType>
                explicit fix_div_by_pos(ContainerType witness, uint8_t m1, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m1, m2)), m1(M(m1)), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_div_by_pos(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};

                fix_div_by_pos(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_div_by_pos =
                fix_div_by_pos<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                               BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                auto m = component.get_m();

                auto x_val = var_value(assignment, instance_input.x);
                auto y_val = var_value(assignment, instance_input.y);

                typename BlueprintFieldType::value_type tmp_mul = x_val * component.get_delta();
                DivMod<BlueprintFieldType> tmp_div =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(tmp_mul, y_val);
                auto z_val = tmp_div.quotient;

                assignment.witness(magic(var_pos.x)) = x_val;
                assignment.witness(magic(var_pos.y)) = y_val;
                assignment.witness(magic(var_pos.z)) = z_val;

                std::vector<uint16_t> q0_val;
                std::vector<uint16_t> a0_val;

                FixedPointHelper<BlueprintFieldType>::abs(y_val);    // For gadgets using this gadget
                auto sign = FixedPointHelper<BlueprintFieldType>::decompose(tmp_div.remainder, q0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                sign = FixedPointHelper<BlueprintFieldType>::decompose(y_val - tmp_div.remainder - 1, a0_val);
                BLUEPRINT_RELEASE_ASSERT(!sign);
                // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                BLUEPRINT_RELEASE_ASSERT(q0_val.size() >= m);
                BLUEPRINT_RELEASE_ASSERT(a0_val.size() >= m);

                auto y_ = FixedPointHelper<BlueprintFieldType>::field_to_backend(y_val);
                assignment.witness(magic(var_pos.c)) = typename BlueprintFieldType::value_type(y_.limbs()[0] & 1);

                for (auto i = 0; i < m; i++) {
                    assignment.witness(var_pos.q0.column() + i, var_pos.q0.row()) = q0_val[i];
                    assignment.witness(var_pos.a0.column() + i, var_pos.a0.row()) = a0_val[i];
                }

                return typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                int64_t start_row_index = 1 - component.rows_amount;
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::var;
                // 2x\Delta_z + y - c = 2zy + 2q and proving 0 <= q < y
                auto m = component.get_m();
                auto delta = component.get_delta();

                auto q = nil::crypto3::math::expression(var(magic(var_pos.q0)));
                auto a = nil::crypto3::math::expression(var(magic(var_pos.a0)));
                for (auto i = 1; i < m; i++) {
                    q += var(var_pos.q0.column() + i, var_pos.q0.row()) * (1ULL << (16 * i));
                    a += var(var_pos.a0.column() + i, var_pos.a0.row()) * (1ULL << (16 * i));
                }

                auto x = var(magic(var_pos.x));
                auto y = var(magic(var_pos.y));
                auto z = var(magic(var_pos.z));
                auto c = var(magic(var_pos.c));

                auto constraint_1 = 2 * (x * delta - y * z - q) + y - c;
                auto constraint_2 = (c - 1) * c;
                auto constraint_3 = y - q - a - 1;

                return bp.add_gate({constraint_1, constraint_2, constraint_3});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_lookup_gates(
                const plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {
                const int64_t start_row_index = 1 - static_cast<int64_t>(component.rows_amount);
                const auto var_pos = component.get_var_pos(start_row_index);
                auto m = component.get_m();

                const std::map<std::string, std::size_t> &lookup_tables_indices = bp.get_reserved_indices();

                using var = typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::var;
                using constraint_type = typename crypto3::zk::snark::plonk_lookup_constraint<BlueprintFieldType>;
                using range_table =
                    typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::range_table;

                std::vector<constraint_type> constraints;
                constraints.reserve(2 * m);

                auto table_id = lookup_tables_indices.at(range_table::FULL_TABLE_NAME);
                BLUEPRINT_RELEASE_ASSERT(var_pos.q0.row() == var_pos.a0.row());

                for (auto i = 0; i < m; i++) {
                    constraint_type constraint_q, constraint_a;
                    constraint_q.table_id = table_id;
                    constraint_a.table_id = table_id;

                    // We put row=0 here and enable the selector in the correct one
                    auto qi = var(var_pos.q0.column() + i, 0);
                    auto ai = var(var_pos.a0.column() + i, 0);
                    constraint_q.lookup_input = {qi};
                    constraint_a.lookup_input = {ai};
                    constraints.push_back(constraint_q);
                    constraints.push_back(constraint_a);
                }

                return bp.add_lookup_gate(constraints);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                using var = typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::var;

                var x = var(magic(var_pos.x), false);
                var y = var(magic(var_pos.y), false);
                bp.add_copy_constraint({instance_input.x, x});
                bp.add_copy_constraint({instance_input.y, y});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // selector goes onto last row and gate uses all rows
                assignment.enable_selector(selector_index, start_row_index + component.rows_amount - 1);

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                std::size_t lookup_selector_index = generate_lookup_gates(component, bp, assignment, instance_input);
                assignment.enable_selector(lookup_selector_index, var_pos.a0.row());    // same as q0.row()
#endif

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_div_by_pos<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_DIV_BY_POSITIVE_HPP
