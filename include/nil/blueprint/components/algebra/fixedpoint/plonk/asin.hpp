#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASIN_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASIN_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/sqrt.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/sqrt_floor.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/div_by_positive.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/atan.hpp"

namespace nil {
    namespace blueprint {
        namespace components {
            // Works by evaluating asin(x) = atan(x / sqrt(1 - x^2))
            // The range of 1 <= x <= 1 is enforced by the sqrt component

            /**
             * Component representing a asin operation with input x and output y, where y = asin(x).
             *
             * The delta of y is equal to the delta of x.
             *
             * Input:    x  ... field element
             * Output:   y  ... asin(x) (field element)
             */
            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_asin;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_asin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0> {

            public:
                using value_type = typename BlueprintFieldType::value_type;

                using sqrt_component =
                    fix_sqrt<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using sqrt_floor_component = fix_sqrt_floor<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using atan_component =
                    fix_atan<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;
                using div_by_pos_component = fix_div_by_pos<
                    crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            private:
                sqrt_component sqrt;
                sqrt_floor_component sqrt_floor;
                atan_component atan;
                div_by_pos_component div;

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

                static std::size_t gates_amount_internal(uint8_t m1, uint8_t m2) {
                    auto gate_amount = atan_component::gates_amount + div_by_pos_component::gates_amount;
                    if (m2 == 1) {
                        gate_amount += sqrt_component::gates_amount;
                    } else {
                        gate_amount += sqrt_floor_component::gates_amount;
                    }

#ifdef TEST_WITHOUT_LOOKUP_TABLES
                    return gate_amount + 1;
#else
                    return gate_amount + 2;
#endif
                }

                sqrt_component instantiate_sqrt(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = sqrt_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return sqrt_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                          m1, m2);
                }

                sqrt_floor_component instantiate_sqrt_floor(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = sqrt_floor_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return sqrt_floor_component(witness_list, std::array<std::uint32_t, 0>(),
                                                std::array<std::uint32_t, 0>(), m1, m2);
                }

                atan_component instantiate_atan(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = atan_component::get_witness_columns(m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return atan_component(witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(),
                                          m1, m2);
                }

                div_by_pos_component instantiate_div(uint8_t m1, uint8_t m2) const {
                    std::vector<std::uint32_t> witness_list;
                    auto witness_columns = div_by_pos_component::get_witness_columns(this->witness_amount(), m1, m2);
                    BLUEPRINT_RELEASE_ASSERT(this->witness_amount() >= witness_columns);
                    witness_list.reserve(witness_columns);
                    for (auto i = 0; i < witness_columns; i++) {
                        witness_list.push_back(this->W(i));
                    }
                    return div_by_pos_component(witness_list, std::array<std::uint32_t, 0>(),
                                                std::array<std::uint32_t, 0>(), m1, m2);
                }

            public:
                uint8_t get_m() const {
                    return atan.get_m();
                }

                uint8_t get_m1() const {
                    return atan.get_m1();
                }

                uint8_t get_m2() const {
                    return atan.get_m2();
                }

                uint64_t get_delta() const {
                    return atan.get_delta();
                }

                static std::size_t get_witness_columns(std::size_t witness_amount, uint8_t m1, uint8_t m2) {
                    auto sqrt_witnesses = 0;
                    if (m2 == 1) {
                        sqrt_witnesses = sqrt_component::get_witness_columns(witness_amount, m1, m2);
                    } else {
                        sqrt_witnesses = sqrt_floor_component::get_witness_columns(witness_amount, m1, m2);
                    }
                    return std::max(sqrt_witnesses,
                                    std::max(atan_component::get_witness_columns(m1, m2),
                                             div_by_pos_component::get_witness_columns(m1, m2)));
                }

                struct var_positions {
                    CellPosition x, y, sqrt_in, q0, atan_out, add_off, mul_off;
                    int64_t atan_row, div_row, sqrt_row, asin_row;
                };

                var_positions get_var_pos(const int64_t start_row_index) const {

                    // trace layout witness (atan col(s)), constant (2 col(s))
                    //
                    //                |               witness                |     constant      |
                    //       r\c      | 0 | 1 |    2   |     3     |  4 | .. |  0     |    1     |
                    // +--------------+---+------+-------+---------+---------+--------+----------|
                    // | atan_rows    |             <atan_witness>           |   <atan_const>    |
                    // | sqrt_row(s)  |             <sqrt_witness>           |   <sqrt_const>    |
                    // | div_row(s)   |              <div_witness>           |   <div_const>     |
                    // |     0        | x | y | sqrt_in | atan_out | q0 | .. | add_off | mul_off |

                    auto m2 = this->get_m2();

                    var_positions pos;
                    pos.atan_row = start_row_index;
                    pos.div_row = pos.atan_row + atan.rows_amount;
                    pos.sqrt_row = pos.div_row + div.rows_amount;
                    pos.asin_row = pos.sqrt_row;
                    if (m2 == 1) {
                        pos.asin_row += sqrt.rows_amount;
                    } else {
                        pos.asin_row += sqrt_floor.rows_amount;
                    }

                    pos.x = CellPosition(this->W(0), pos.asin_row);
                    pos.y = CellPosition(this->W(1), pos.asin_row);
                    pos.sqrt_in = CellPosition(this->W(2), pos.asin_row);
                    pos.atan_out = CellPosition(this->W(3), pos.asin_row);
                    pos.q0 = CellPosition(this->W(4 + 0 * m2), pos.asin_row);    // occupies m2 cells

                    pos.add_off = CellPosition(this->C(0), pos.asin_row);
                    pos.mul_off = CellPosition(this->C(1), pos.asin_row);
                    return pos;
                }

                const sqrt_component &get_sqrt_component() const {
                    return sqrt;
                }

                const sqrt_floor_component &get_sqrt_floor_component() const {
                    return sqrt_floor;
                }

                const atan_component &get_atan_component() const {
                    return atan;
                }

                const div_by_pos_component &get_div_by_pos_component() const {
                    return div;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::lookup_table_definition<BlueprintFieldType>;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    uint8_t m1;
                    uint8_t m2;

                    gate_manifest_type(uint8_t m1, uint8_t m2) : m1(m1), m2(m2) {
                    }

                    std::uint32_t gates_amount() const override {
                        return fix_asin::gates_amount_internal(this->m1, this->m2);
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint8_t m1, uint8_t m2) {
                    gate_manifest manifest = gate_manifest(gate_manifest_type(m1, m2));
                    manifest.merge_with(
                        atan_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2));
                    manifest.merge_with(
                        div_by_pos_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2));
                    if (m2 == 1) {
                        manifest.merge_with(
                            sqrt_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2));
                    } else {
                        manifest.merge_with(
                            sqrt_floor_component::get_gate_manifest(witness_amount, lookup_column_amount, m1, m2));
                    }
                    return manifest;
                }

                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(4 + m2)), true);
                    manifest.merge_with(atan_component::get_manifest(m1, m2));
                    manifest.merge_with(div_by_pos_component::get_manifest(m1, m2));
                    if (m2 == 1) {
                        manifest.merge_with(sqrt_component::get_manifest(m1, m2));
                    } else {
                        manifest.merge_with(sqrt_floor_component::get_manifest(m1, m2));
                    }
                    return manifest;
                }

                static std::size_t get_rows_amount(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                   uint8_t m1, uint8_t m2) {
                    auto rows = 1 + atan_component::get_rows_amount(witness_amount, lookup_column_amount) +
                                div_by_pos_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    if (m2 == 1) {
                        rows += sqrt_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    } else {
                        rows += sqrt_floor_component::get_rows_amount(witness_amount, lookup_column_amount, m1, m2);
                    }
                    return rows;
                }

                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, get_m1(), get_m2());

                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<std::reference_wrapper<var>> all_vars() {
                        return {x};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_asin &component, std::uint32_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    result_type(const fix_asin &component, std::size_t start_row_index) {
                        const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));
                        output = var(splat(var_pos.y), false);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    // just the range table
                    return atan.component_custom_lookup_tables();
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    // just the range table
                    return atan.component_lookup_tables();
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_asin(WitnessContainerType witness, ConstantContainerType constant,
                         PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    sqrt(instantiate_sqrt(m1, m2)), sqrt_floor(instantiate_sqrt_floor(m1, m2)),
                    atan(instantiate_atan(m1, m2)), div(instantiate_div(m1, m2)) {
                    ;
                };

                fix_asin(std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                         std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                         std::initializer_list<typename component_type::public_input_container_type::value_type>
                             public_inputs,
                         uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    sqrt(instantiate_sqrt(m1, m2)), sqrt_floor(instantiate_sqrt_floor(m1, m2)),
                    atan(instantiate_atan(m1, m2)), div(instantiate_div(m1, m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_asin =
                fix_asin<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                         BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::result_type generate_assignments(
                const plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::input_type
                    instance_input,
                const std::uint32_t start_row_index) {

                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                // TOOD

                return typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                // TODO

                return typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_asin<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {
                const auto var_pos = component.get_var_pos(static_cast<int64_t>(start_row_index));

                // TODO
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_ASIN_HPP
