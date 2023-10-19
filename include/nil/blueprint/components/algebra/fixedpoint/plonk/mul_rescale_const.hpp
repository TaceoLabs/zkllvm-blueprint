#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_CONST_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_CONST_HPP

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

            // Input: x, y as Fixedpoint numbers with \Delta_x = \Delta_y, y is public
            // Output: z = Rescale(x * y) with \Delta_z = \Delta_x = \Delta_y

            // Works by proving z = round(x*y/\Delta) via 2xy + \Delta = 2z\Delta + 2q and proving 0 <= q < \Delta via a
            // lookup table

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_mul_rescale_const;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_mul_rescale_const<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0> {

            private:
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

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 1, 0>;

                using var = typename component_type::var;
                using value_type = typename BlueprintFieldType::value_type;
                using manifest_type = plonk_component_manifest;

                value_type constant;

                class gate_manifest_type : public component_gate_manifest {
                public:
                    std::uint32_t gates_amount() const override {
                        return fix_mul_rescale_const::gates_amount;
                    }
                };

                static gate_manifest get_gate_manifest(std::size_t witness_amount, std::size_t lookup_column_amount) {
                    static gate_manifest manifest = gate_manifest(gate_manifest_type());
                    return manifest;
                }

                // TACEO_TODO Update to lookup tables
                static manifest_type get_manifest(uint8_t m2) {
                    static manifest_type manifest = manifest_type(
                        std::shared_ptr<manifest_param>(new manifest_single_value_param(2 + M(m2))), true);
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
                    result_type(const fix_mul_rescale_const &component, std::uint32_t start_row_index) {
                        output = var(component.W(1), start_row_index, false, var::column_type::witness);
                    }

                    result_type(const fix_mul_rescale_const &component, std::size_t start_row_index) {
                        output = var(component.W(1), start_row_index, false, var::column_type::witness);
                    }

                    std::vector<var> all_vars() const {
                        return {output};
                    }
                };

                template<typename ContainerType>
                explicit fix_mul_rescale_const(ContainerType witness, value_type constant_, uint8_t m2) :
                    component_type(witness, {}, {}, get_manifest(m2)), constant(constant_), m2(M(m2)) {};

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_mul_rescale_const(WitnessContainerType witness, ConstantContainerType constant,
                                      PublicInputContainerType public_input, value_type constant_, int8_t m2) :
                    component_type(witness, constant, public_input, get_manifest(m2)),
                    constant(constant_), m2(M(m2)) {};

                fix_mul_rescale_const(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    value_type constant_, uint8_t m2) :
                    component_type(witnesses, constants, public_inputs, get_manifest(m2)),
                    constant(constant_), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_mul_rescale_const = fix_mul_rescale_const<
                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType,
                                                                      ArithmetizationParams>::input_type instance_input,
                    const std::uint32_t start_row_index) {

                const std::size_t j = start_row_index;

                typename BlueprintFieldType::value_type tmp =
                    var_value(assignment, instance_input.x) * component.constant;

                DivMod<BlueprintFieldType> res =
                    FixedPointHelper<BlueprintFieldType>::round_div_mod(tmp, component.get_delta());

                // | x | z | q0 | ... |
                assignment.witness(component.W(0), j) = var_value(assignment, instance_input.x);
                assignment.witness(component.W(1), j) = res.quotient;

                if (component.get_m2() == 1) {
                    assignment.witness(component.W(2), j) = res.remainder;
                } else {
                    std::vector<uint16_t> decomp;
                    bool sign = FixedPointHelper<BlueprintFieldType>::decompose(res.remainder, decomp);
                    BLUEPRINT_RELEASE_ASSERT(!sign);
                    // is ok because decomp is at least of size 4 and the biggest we have is 32.32
                    BLUEPRINT_RELEASE_ASSERT(decomp.size() >= component.get_m2());
                    for (auto i = 0; i < component.get_m2(); i++) {
                        assignment.witness(component.W(2 + i), j) = decomp[i];
                    }
                }

                return
                    typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            std::size_t generate_gates(
                const plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input) {

                using var = typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::var;
                // 2xy + \Delta = 2z\Delta + 2q and proving 0 <= q < \Delta via a lookup table. Delta is a multiple of
                // 2^16, hence q could be decomposed into 16-bit limbs
                auto delta = component.get_delta();

                auto q = nil::crypto3::math::expression(var(component.W(2), 0));
                for (auto i = 1; i < component.get_m2(); i++) {
                    q += var(component.W(2 + i), 0) * (1ULL << (16 * i));
                }

                auto constraint_1 =
                    2 * (var(component.W(0), 0) * var(component.C(0), 0, true, var::column_type::constant) -
                         var(component.W(1), 0) * delta - q) +
                    delta;

                // TACEO_TODO extend for lookup constraint
                return bp.add_gate(constraint_1);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_copy_constraints(
                const plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::var;

                const std::size_t j = start_row_index;
                var component_x = var(component.W(0), static_cast<int>(j), false);
                bp.add_copy_constraint({instance_input.x, component_x});
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_circuit(
                    const plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams> &component,
                    circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_mul_rescale_const<
                        BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                    const std::size_t start_row_index) {

                // TACEO_TODO extend for lookup?
                std::size_t selector_index = generate_gates(component, bp, assignment, instance_input);

                assignment.enable_selector(selector_index, start_row_index);

                generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
                generate_assignments_constant(component, assignment, instance_input, start_row_index);

                return
                    typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::result_type(
                        component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            void generate_assignments_constant(
                const plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams> &component,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_mul_rescale_const<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                assignment.constant(component.C(0), start_row_index) = component.constant;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_MUL_RESCALE_CONST_HPP
