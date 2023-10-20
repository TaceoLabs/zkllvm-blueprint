#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/exp.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/plonk/range.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            // Input: x as fixedpoint numbers with \Delta_x
            // Output: y as fixedpoint number with huge scale!

            // Works by decomposing to the pre-comma part and, depending on \Delta_x, one or two 16-bit post-comma parts
            // and fusing lookup tables: y = exp(x) = exp(x_pre) * exp(x_post1) * exp(x_post2)

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_exp_ranged;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_exp_ranged<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
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

            private:
                exp_component exp;
                range_component range;

                // TODO update!
                static constexpr value_type lo = 0;
                static constexpr value_type hi = 0;

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

            public:
                const exp_component &get_exp_component() const {
                    return exp;
                }

                const range_component &get_range_component() const {
                    return range;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 0>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_exp_ranged::gates_amount;
                    }
                };

                // TODO Update
                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                // TODO Update
                static manifest_type get_manifest(uint8_t m1, uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(4 + 2 * M(m2))), false);
                    return manifest;
                }

                // TODO Update
                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount) {
                    return 1;
                }

                // TODO Update
                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0);

                // TODO Update
                struct input_type {
                    var x = var(0, 0, false);

                    std::vector<var> all_vars() const {
                        return {x};
                    }
                };

                using result_type = typename exp_component::result_type;

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_exp_ranged(WitnessContainerType witness, ConstantContainerType constant,
                               PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m1, m2)),
                    exp(instantiate_exp(m2)), range(instantiate_range(m1, m2, lo, hi)) {};

                fix_exp_ranged(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m1, m2)),
                    exp(instantiate_exp(m2)), range(instantiate_range(m1, m2, lo, hi)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_exp_ranged =
                fix_exp_ranged<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                               BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            // TODO Update
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                // First, we put the range gadget into the trace
                // Then, we add the exp gadget into new rows

                auto range_comp = component.get_range_component();
                auto range_result = generate_assignments(range_comp, assignment, instance_input, start_row_index);

                auto range_rows = range_comp.get_rows_amount();

                auto exp_comp = component.get_exp_component();
                auto exp_result =
                    generate_assignments(exp_comp, assignment, range_result.output, start_row_index + range_rows);

                return exp_result;
            }

            // TODO Update
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::var;
                // auto m2 = component.get_m2();
                // auto delta = component.get_delta();
                // uint32_t table_half = FixedPointTables<BlueprintFieldType>::ExpALen / 2;

                // auto constraint_1 = delta * (var(component.W(2), 0) - table_half) - var(component.W(0), 0);
                // auto constraint_2 = nil::crypto3::math::expression(var(component.W(3), 0) * var(component.W(5), 0));

                // if (m2 == 2) {
                //     constraint_1 += (1ULL << 16) * var(component.W(4), 0) + var(component.W(6), 0);
                //     constraint_2 *= var(component.W(7), 0);
                // } else {
                //     constraint_1 += var(component.W(4), 0);
                // }
                // constraint_2 -= var(component.W(1), 0);

                // // TACEO_TODO extend for lookup constraint
                // return bp.add_gate({constraint_1, constraint_2});
                return bp.add_gate({});
            }

            // TODO Update
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
            }

            // TODO Update
            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                // Enable the range component
                auto range_comp = component.get_range_component();
                auto result = generate_circuit(range_comp, bp, assignment, instance_input, start_row_index);

                // std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                // assignment.enable_selector(selector_index, start_row_index);

                // generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_exp_ranged<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_RANGED_HPP
