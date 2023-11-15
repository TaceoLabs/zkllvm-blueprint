#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TESTER_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TESTER_HPP

#include "nil/blueprint/components/algebra/fixedpoint/plonk/argmax.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/range.hpp"
#include "nil/blueprint/components/algebra/fixedpoint/lookup_tables/exp.hpp"

namespace nil {
    namespace blueprint {
        namespace components {

            enum FixedPointComponents {
                ARGMAX,
                ARGMIN,
                CMP,
                CMP_EXTENDED,
                CMP_MIN_MAX,
                DIV_BY_POS,
                DIV,
                DOT_RESCALE1,
                DOT_RESCALE2,
                EXP,
                EXP_RANGED,
                GATHER_ACC,
                LOG,
                MAX,
                MIN,
                MUL_RESCALE,
                MUL_RESCALE_CONST,
                NEG,
                RANGE,
                REM,
                RESCALE,
                SELECT,
                SQRT,
                SQRT_FLOOR,
                TANH,
                TO_FIXEDPOINT
            };

            static constexpr uint8_t TESTER_MAX_CONSTANT_COLS = 2;
            static constexpr uint8_t TESTER_MAX_PUBLIC_COLS = 10;

            template<typename ArithmetizationType, typename FieldType, typename NonNativePolicyType>
            class fix_tester;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename NonNativePolicyType>
            class fix_tester<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                             BlueprintFieldType, NonNativePolicyType>
                : public plonk_component<BlueprintFieldType, ArithmetizationParams, TESTER_MAX_CONSTANT_COLS,
                                         TESTER_MAX_PUBLIC_COLS> {
            public:
                using value_type = typename BlueprintFieldType::value_type;

                struct testcase {
                    FixedPointComponents component;
                    std::vector<value_type> inputs;
                    std::vector<value_type> outputs;
                    std::vector<value_type> constants;
                };

            private:
                std::vector<testcase> testcases;

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

                const std::vector<testcase> &get_testcases() const {
                    return testcases;
                }

                static std::size_t get_component_rows_amount(FixedPointComponents component, std::size_t witness_amount,
                                                             std::size_t lookup_column_amount, uint8_t m1, uint8_t m2) {
                    switch (component) {
                        case FixedPointComponents::ARGMAX:
                            return fix_argmax<
                                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, NonNativePolicyType>::get_rows_amount(witness_amount,
                                                                                          lookup_column_amount, m1, m2);
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false);
                    }
                    return 0;
                }

                void add_testcase(FixedPointComponents component, std::vector<value_type> &inputs,
                                  std::vector<value_type> &outputs, std::vector<value_type> &constants) {
                    testcase test;
                    test.component = component;
                    test.inputs = inputs;
                    test.outputs = outputs;
                    test.constants = constants;
                    testcases.push_back(test);
                    rows_amount += get_component_rows_amount(component, this->witness_amount(), 0, m1, m2);
                }

                std::vector<std::uint32_t> get_witness_list() const {
                    std::vector<std::uint32_t> result;
                    result.reserve(this->witness_amount());
                    for (std::size_t i = 0; i < this->witness_amount(); ++i) {
                        result.push_back(this->W(i));
                    }
                    return result;
                }

                std::array<std::uint32_t, TESTER_MAX_CONSTANT_COLS> get_constant_list() const {
                    std::array<std::uint32_t, TESTER_MAX_CONSTANT_COLS> result;
                    for (std::size_t i = 0; i < this->constant_amount(); ++i) {
                        result[i] = this->C(i);
                    }
                    return result;
                }

                std::array<std::uint32_t, TESTER_MAX_PUBLIC_COLS> get_public_input_list() const {
                    std::array<std::uint32_t, TESTER_MAX_PUBLIC_COLS> result;
                    for (std::size_t i = 0; i < this->public_input_amount(); ++i) {
                        result[i] = this->PI(i);
                    }
                    return result;
                }

                using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams,
                                                       TESTER_MAX_CONSTANT_COLS, TESTER_MAX_PUBLIC_COLS>;

                using var = typename component_type::var;
                using manifest_type = plonk_component_manifest;
                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using range_table = fixedpoint_range_table<BlueprintFieldType>;

                static manifest_type get_manifest() {
                    static manifest_type manifest =
                        manifest_type(std::shared_ptr<manifest_param>(new manifest_single_value_param(1)), false);
                    return manifest;
                }

                std::size_t rows_amount = 0;

                struct input_type {

                    std::vector<var> all_vars() const {
                        return {};
                    }
                };

                struct result_type {

                    result_type(const fix_tester &component, std::uint32_t start_row_index) {
                    }

                    result_type(const fix_tester &component, std::size_t start_row_index) {
                    }

                    std::vector<var> all_vars() const {
                        return {};
                    }
                };

// Allows disabling the lookup tables for faster testing
#ifndef TEST_WITHOUT_LOOKUP_TABLES
                std::vector<std::shared_ptr<lookup_table_definition>> component_custom_lookup_tables() {
                    std::vector<std::shared_ptr<lookup_table_definition>> result = {};
                    auto table = std::shared_ptr<lookup_table_definition>(new range_table());

                    if (m2 == 1) {
                        auto table_a = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_exp_a16_table<BlueprintFieldType>());
                        auto table_b = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_exp_b16_table<BlueprintFieldType>());
                        result.push_back(table_a);
                        result.push_back(table_b);
                    } else if (m2 == 2) {
                        auto table_a = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_exp_a32_table<BlueprintFieldType>());
                        auto table_b = std::shared_ptr<lookup_table_definition>(
                            new fixedpoint_exp_b32_table<BlueprintFieldType>());
                        result.push_back(table_a);
                        result.push_back(table_b);
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    result.push_back(table);
                    return result;
                }

                std::map<std::string, std::size_t> component_lookup_tables() {
                    std::map<std::string, std::size_t> lookup_tables;
                    lookup_tables[range_table::FULL_TABLE_NAME] = 0;    // REQUIRED_TABLE

                    if (m2 == 1) {
                        lookup_tables[fixedpoint_exp_a16_table<BlueprintFieldType>::FULL_TABLE_NAME] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_exp_b16_table<BlueprintFieldType>::FULL_TABLE_NAME] =
                            0;    // REQUIRED_TABLE
                    } else if (m2 == 2) {
                        lookup_tables[fixedpoint_exp_a32_table<BlueprintFieldType>::FULL_TABLE_NAME] =
                            0;    // REQUIRED_TABLE
                        lookup_tables[fixedpoint_exp_b32_table<BlueprintFieldType>::FULL_TABLE_NAME] =
                            0;    // REQUIRED_TABLE
                    } else {
                        BLUEPRINT_RELEASE_ASSERT(false);
                    }

                    return lookup_tables;
                }
#endif

                template<typename WitnessContainerType, typename ConstantContainerType,
                         typename PublicInputContainerType>
                fix_tester(WitnessContainerType witness, ConstantContainerType constant,
                           PublicInputContainerType public_input, uint8_t m1, uint8_t m2) :
                    component_type(witness, constant, public_input, get_manifest()),
                    m1(M(m1)), m2(M(m2)) {};

                fix_tester(
                    std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                    std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                    std::initializer_list<typename component_type::public_input_container_type::value_type>
                        public_inputs,
                    uint8_t m1, uint8_t m2, value_type index_y_, bool select_last_index) :
                    component_type(witnesses, constants, public_inputs, get_manifest()),
                    m1(M(m1)), m2(M(m2)) {};
            };

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            using plonk_fixedpoint_tester =
                fix_tester<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                           BlueprintFieldType, basic_non_native_policy<BlueprintFieldType>>;

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type
                generate_assignments(
                    const plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams> &component,
                    assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                        &assignment,
                    const typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::input_type
                        instance_input,
                    const std::uint32_t start_row_index) {

                using var = typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::var;

                auto witness_list = component.get_witness_list();
                auto constant_list = component.get_constant_list();
                auto public_input_list = component.get_public_input_list();

                auto current_row_index = start_row_index;

                for (auto &test : component.get_testcases()) {
                    auto &inputs = test.inputs;
                    auto &outputs = test.outputs;
                    auto &constants = test.constants;

                    BLUEPRINT_RELEASE_ASSERT(inputs.size() + outputs.size() <= public_input_list.size());

                    // Put inputs and outputs in the public columns, we will have coppy constraints to them later
                    for (std::size_t i = 0; i < inputs.size(); ++i) {
                        assignment.public_input(component.PI(i), current_row_index) = inputs[i];
                    }
                    for (std::size_t i = 0; i < outputs.size(); ++i) {
                        assignment.public_input(component.PI(i + inputs.size()), current_row_index) = outputs[i];
                    }

                    switch (test.component) {
                        case FixedPointComponents::ARGMAX: {
                            using new_component_type = fix_argmax<
                                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

                            // Inputs
                            typename new_component_type::input_type instance_input {
                                var(component.PI(0), current_row_index, false, var::column_type::public_input),
                                var(component.PI(1), current_row_index, false, var::column_type::public_input),
                                var(component.PI(2), current_row_index, false, var::column_type::public_input)};
                            BLUEPRINT_RELEASE_ASSERT(instance_input.all_vars().size() == inputs.size());

                            // Assign component
                            bool select_last_index = constants[1] == 0 ? false : true;
                            new_component_type component_instance(witness_list, constant_list, public_input_list,
                                                                  component.get_m1(), component.get_m2(), constants[0],
                                                                  select_last_index);
                            auto instance_result =
                                generate_assignments(component_instance, assignment, instance_input, current_row_index);

                            // Outputs
                            auto vars = instance_result.all_vars();
                            BLUEPRINT_RELEASE_ASSERT(vars.size() == outputs.size());
                            for (auto i = 0; i < vars.size(); i++) {
                                BLUEPRINT_RELEASE_ASSERT(var_value(assignment, vars[i]) == outputs[i]);
                            }

                            current_row_index += component_instance.rows_amount;
                            break;
                        }
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false);
                    }
                }

                return typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

            template<typename BlueprintFieldType, typename ArithmetizationParams>
            typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type generate_circuit(
                const plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams> &component,
                circuit<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>
                    &assignment,
                const typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::input_type
                    &instance_input,
                const std::size_t start_row_index) {

                using var = typename plonk_fixedpoint_argmax<BlueprintFieldType, ArithmetizationParams>::var;

                auto witness_list = component.get_witness_list();
                auto constant_list = component.get_constant_list();
                auto public_input_list = component.get_public_input_list();

                auto current_row_index = start_row_index;

                for (auto &test : component.get_testcases()) {
                    auto &inputs = test.inputs;
                    auto &outputs = test.outputs;
                    auto &constants = test.constants;

                    BLUEPRINT_RELEASE_ASSERT(inputs.size() + outputs.size() <= public_input_list.size());

                    switch (test.component) {
                        case FixedPointComponents::ARGMAX: {
                            using new_component_type = fix_argmax<
                                crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

                            // Inputs
                            typename new_component_type::input_type instance_input {
                                var(component.PI(0), current_row_index, false, var::column_type::public_input),
                                var(component.PI(1), current_row_index, false, var::column_type::public_input),
                                var(component.PI(2), current_row_index, false, var::column_type::public_input)};
                            BLUEPRINT_RELEASE_ASSERT(instance_input.all_vars().size() == inputs.size());

                            // layout component
                            bool select_last_index = constants[1] == 0 ? false : true;
                            new_component_type component_instance(witness_list, constant_list, public_input_list,
                                                                  component.get_m1(), component.get_m2(), constants[0],
                                                                  select_last_index);
                            auto instance_result =
                                generate_circuit(component_instance, bp, assignment, instance_input, current_row_index);

                            // Copy constraints for outputs
                            auto vars = instance_result.all_vars();
                            BLUEPRINT_RELEASE_ASSERT(vars.size() == outputs.size());
                            for (auto i = 0; i < vars.size(); i++) {
                                bp.add_copy_constraint({var(component.PI(i + inputs.size()), current_row_index, false,
                                                            var::column_type::public_input),
                                                        vars[i]});
                            }

                            current_row_index += component_instance.rows_amount;
                            break;
                        }
                        default:
                            BLUEPRINT_RELEASE_ASSERT(false);
                    }
                }

                return typename plonk_fixedpoint_tester<BlueprintFieldType, ArithmetizationParams>::result_type(
                    component, start_row_index);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TESTER_HPP
