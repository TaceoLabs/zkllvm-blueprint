#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_mul_rescale_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/mul_rescale.hpp>

#include "../../../test_plonk_component.hpp"

#include <nil/blueprint/components/algebra/fixedpoint/type.hpp>

using namespace nil;
using nil::blueprint::components::FixedPoint;

bool doubleEquals(double left, double right, double epsilon) {
    return (fabs(left - right) < epsilon);
}

template<typename FieldType>
void test_fixedpoint_mul_rescale(FixedPoint<FieldType> input1, FixedPoint<FieldType> input2) {
    using BlueprintFieldType = FieldType;
    constexpr std::size_t WitnessColumns = 4;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::mul_rescale<ArithmetizationType,
                                           BlueprintFieldType,
                                           nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input),
                                                          var(0, 1, false, var::column_type::public_input)};

    // TACEO_TODO update
    double expected_res = input1.to_double() * input2.to_double();

    auto result_check = [&expected_res, input1, input2](AssignmentType &assignment,
                                                        typename component_type::result_type &real_res) {
        double real_res_f =
            FixedPoint<FieldType>(var_value(assignment, real_res.output), FixedPoint<FieldType>::SCALE).to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point mul test: "
                  << "\n";
        std::cout << "input   : " << input1.to_double() << " " << input2.to_double() << "\n";
        std::cout << "expected: " << expected_res << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        if (!doubleEquals(expected_res, real_res_f, 0.0001)) {
            std::cout << "expected: " << expected_res << "\n";
            std::cout << "real    : " << real_res_f << "\n\n";
            abort();
        }
        assert(expected_res == var_value(assignment, real_res.output));
    };

    component_type component_instance({0, 1, 2, 3}, {}, {});

    std::vector<typename FieldType::value_type> public_input = {input1.get_value(), input2.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FieldType>
void test_components(int i, int j) {
    // TACEO_TODO mul_by_const
    // TACEO_TODO bring to fixed_point

    FixedPoint<FieldType> x((int64_t)i);
    FixedPoint<FieldType> y((int64_t)j);

    // test_add<FieldType>({i, j});
    // test_sub<FieldType>({i, j});
    test_fixedpoint_mul_rescale<FieldType>(x, y);
    // test_mul_by_const<FieldType>({i}, j);
    // test_div_or_zero<FieldType>({i, j});
}

// template<typename FieldType>
// void test_components_on_random_data() {
//     nil::crypto3::random::algebraic_engine<FieldType> generate_random;
//     boost::random::mt19937 seed_seq;
//     generate_random.seed(seed_seq);

//     // TACEO_TODO bring in range
//     // TACEO_TODO mul_by_const
//     typename FieldType::value_type i = generate_random();
//     typename FieldType::value_type j = generate_random();

//     // test_add<FieldType>({i, j});
//     // test_sub<FieldType>({i, j});
//     test_fixedpoint_mul_rescale<FieldType>({i, j});
//     // test_mul_by_const<FieldType>({i}, j);
//     // test_div_or_zero<FieldType>({i, j});
// }

template<typename FieldType, std::size_t RandomTestsAmount>
void field_operations_test() {
    for (int i = -2; i < 3; i++) {
        for (int j = -2; j < 3; j++) {
            test_components<FieldType>(i, j);
        }
    }

    // for (std::size_t i = 0; i < RandomTestsAmount; i++) {
    //     test_components_on_random_data<FieldType>();
    // }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_mul_rescale_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_mul_rescale_tes_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_mul_rescale_tes_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<field_type, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()