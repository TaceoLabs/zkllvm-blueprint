#ifndef CRYPTO3_BLUEPRINT_plonk_fixedpoint_dot_rescale_HPP
#define CRYPTO3_BLUEPRINT_plonk_fixedpoint_dot_rescale_HPP

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

            // Input: vec{x}, vec{y} as Fixedpoint numbers with \Delta_x = \Delta_y
            // Output: z = Rescale(sum_i x_i * y_i) with \Delta_z = \Delta_x = \Delta_y

            // Works by proving z = round(sum/\Delta) via 2 sum + \Delta = 2z\Delta + 2q and proving 0 <= q < \Delta via
            // a lookup table

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_dot_rescale;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_dot_rescale<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 0, 0> {

            private:
                uint32_t dots;
                uint8_t m2;    // Post-comma 16-bit limbs

                static uint8_t M(uint8_t m) {
                    if (m == 0 || m > 2) {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return m;
                }

            public:
                uint8_t get_m2() const {
                    return m2;
                }

                uint64_t get_delta() const {
                    return 1ULL << (16 * m2);
                }

                std::pair<std::size_t, std::size_t> position(std::size_t start_row_index,
                                                             std::size_t column_index) const {
                    std::size_t row = start_row_index + column_index / this->witness_amount();
                    std::size_t column = column_index % this->witness_amount();
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
                        return fix_dot_rescale::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount,
                                                       uint16_t dots, uint8_t m2) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type(dots, m2));
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint32_t dots, uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(1 + 2 * dots + M(m2))), false);
                    return manifest;
                }

                constexpr static std::size_t get_rows_amount(std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint32_t dots,
                                                             uint8_t m2) {
                    uint32_t witnesses = 1 + 2 * dots + M(m2);
                    uint32_t div = witnesses / witness_amount;
                    uint32_t mod = witnesses % witness_amount;
                    if (mod != 0) {
                        div++;
                    }
                    return div;
                }

                constexpr static const std::size_t gates_amount = 1;
                const std::size_t rows_amount = get_rows_amount(this->witness_amount(), 0, dots, m2);

                struct input_type {
                    std::vector<var> x;
                    std::vector<var> y;

                    std::vector<std::vector<var>> all_vars() const {
                        return {x, y};
                    }
                };

                struct result_type {
                    var output = var(0, 0, false);
                    result_type(const fix_dot_rescale &component, std::uint32_t start_row_index) {
                        output = var(component.W(0), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const fix_dot_rescale &component, std::size_t start_row_index) {
                        output = var(component.W(0), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_dot_rescale(ContainerType witness, uint32_t dots, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(dots, m2)), dots(dots), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_dot_rescale(WitnessContainerType witness, ConstantContainerType constant,
                                PublicInputContainerType public_input, uint32_t dots, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(dots, m2)),
                    dots(dots), m2(M(m2)) {};

                fix_dot_rescale(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint32_t dots, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(dots, m2)),
                    dots(dots), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_dot_rescale =
                fix_dot_rescale<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void assign_witness(
                const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                typename BlueprintFieldType::value_type value, std::size_t row_index, std::size_t offset) {
                auto pos = component.position(row_index, offset);
                assignment.witness(component.W(pos.second), pos.first) = value;
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::var get_constraint_var(
                const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                std::size_t offset) {
                auto pos = component.position(0, offset);
                return var(component.W(pos.second), pos.first);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::var
                get_copy_var(const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                             std::size_t row_index, std::size_t offset) {
                auto pos = component.position(row_index, offset);
                return var(component.W(pos.second), static_cast<int>(pos.first), false);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                BLUEPRINT_RELEASE_ASSERT(instance_input.x.size() == component.dots);
                BLUEPRINT_RELEASE_ASSERT(instance_input.y.size() == component.dots);

                // | z | x1 | y1 | ... | xn | yn | q0 | ...

                typename BlueprintFieldType::value_type sum = 0;

                for (auto i = 0; i < component.dots; i++) {
                    auto x = var_value(assignment, instance_input.x[i]);
                    auto y = var_value(assignment, instance_input.y[i]);
                    auto mul = x * y;

                    assign_witness(component, assignment, x, j, 1 + 2 * i);
                    assign_witness(component, assignment, y, j, 2 + 2 * i);

                    sum += mul;
                }
                DivMod<BlueprintFieldType> res =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(sum, component.get_delta());
                assignment.witness(component.W(0), j) = res.quotient;

                if (component.get_m2() == 1) {
                    assign_witness(component, assignment, res.remainder, j, 1 + 2 * component.dots);
                } else {
                    std::vector<uint16_t> decomp;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(res.remainder, decomp);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                    BLUEPRINT_RELEASE_ASSERT(decomp.size() >= component.get_m2());
                    for (auto i = 0; i < component.get_m2(); i++) {
                        assign_witness(component, assignment, decomp[i], j, 1 + 2 * component.dots + i);
                    }
                }

                return typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::var;
                // 2sum + \Delta = 2z\Delta + 2q and proving 0 <= q < \Delta via a lookup table. Delta is a multiple of
                // 2^16, hence q could be decomposed into 16-bit limbs
                auto delta = component.get_delta();

                nil::crypto3::math::expression<var> dot;
                for (auto i = 0; i < component.dots; i++) {
                    dot += get_constraint_var(component, 1 + 2 * i) * get_constraint_var(component, 2 + 2 * i);
                }

                auto q = nil::crypto3::math::expression(get_constraint_var(component, 1 + 2 * component.dots));
                for (auto i = 1; i < component.get_m2(); i++) {
                    q += var(component.W(1 + 2 * component.dots + i), 0) * (1ULL << (16 * i));
                }

                auto constraint_1 = 2 * (dot - var(component.W(0), 0) * delta - q) + delta;

                // TACEO_TODO extend for lookup constraint
                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;

                for (auto i = 0; i < component.dots; i++) {
                    var component_x = get_copy_var(component, j, 1 + 2 * i);
                    var component_y = get_copy_var(component, j, 2 + 2 * i);
                    bp.add_copy_constraint({instance_input.x[i], component_x});
                    bp.add_copy_constraint({component_y, instance_input.y[i]});
                }
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::input_type
                        &instance_input,
                    const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                return typename plonk_fixedpoint_dot_rescale<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_plonk_fixedpoint_dot_rescale_HPP
