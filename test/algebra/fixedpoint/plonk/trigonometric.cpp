#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_trigonometric_operations_test

// Enable for faster tests
#define TEST_WITHOUT_LOOKUP_TABLES

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/keccak.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/random/mersenne_twister.hpp>

#include <nil/blueprint/blueprint/plonk/assignment.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/type.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/sin.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/cos.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON = 0.01;

#define PRINT_FIXED_POINT_TEST(what)                                            \
    std::cout << "fixed_point " << what << " test:\n";                                     \
    std::cout << "input           : " << input.get_value().data << "\n";        \
    std::cout << "input (float)   : " << input.to_double() << "\n";             \
    std::cout << "expected        : " << expected_res.get_value().data << "\n"; \
    std::cout << "real            : " << real_res_.get_value().data << "\n";    \
    std::cout << "expected (float): " << expected_res_f << "\n";                \
    std::cout << "real (float)    : " << real_res_f << "\n\n";

bool doubleEquals(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    // or just smaller epsilon
    return fabs(a - b) < epsilon || fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

template<typename FixedType>
void test_fixedpoint_sin(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = FixedType::M_2 == 1 ? 10 : 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = FixedType::M_1 == 1 ? 1 : 2;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_sin<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = sin(input.to_double());
    auto expected_res = input.sin();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        PRINT_FIXED_POINT_TEST("sin")
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            PRINT_FIXED_POINT_TEST("sin")
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    std::vector<std::uint32_t> const_list;
    const_list.reserve(ConstantColumns);
    for (auto i = 0; i < ConstantColumns; i++) {
        const_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, const_list, std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}


template<typename FixedType>
void test_fixedpoint_cos(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = FixedType::M_2 == 1 ? 9 : 14;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = FixedType::M_1 == 1 ? 1 : 2;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_cos<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = cos(input.to_double());
    auto expected_res = input.cos();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        PRINT_FIXED_POINT_TEST("cos")
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            PRINT_FIXED_POINT_TEST("cos")
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    std::vector<std::uint32_t> const_list;
    const_list.reserve(ConstantColumns);
    for (auto i = 0; i < ConstantColumns; i++) {
        const_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, const_list, std::array<std::uint32_t, 0>(), FixedType::M_1, FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FieldType, typename RngType>
FieldType generate_random_for_fixedpoint(uint8_t m1, uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    BLUEPRINT_RELEASE_ASSERT(m1 > 0 && m1 < 3);
    BLUEPRINT_RELEASE_ASSERT(m2 > 0 && m2 < 3);
    auto m = m1 + m2;

    uint64_t max = 0;
    if (m == 4) {
        max = -1;
    } else {
        max = (1ull << (16 * m)) - 1;
    }

    distribution dist = distribution(0, max);
    uint64_t x = dist(rng);
    distribution dist_bool = distribution(0, 1);
    bool sign = dist_bool(rng) == 1;
    if (sign) {
        return -FieldType(x);
    } else {
        return FieldType(x);
    }
}

template<typename FixedType, typename RngType>
void test_components_on_random_data(RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    test_fixedpoint_sin<FixedType>(x);
    test_fixedpoint_cos<FixedType>(x);
}

template<typename FixedType>
void test_components(double i) {
    FixedType x(i);
    test_fixedpoint_sin<FixedType>(x);
    test_fixedpoint_cos<FixedType>(x);
}

template<typename FixedType, std::size_t RandomTestsAmount>
void field_operations_test() {
    constexpr double pi_half = 1.5707963267948966;
    constexpr double pi = 3.141592653589793;
    constexpr double pi_two = 6.283185307179586;

    for (int i = -2; i < 3; i++) {
        auto i_dbl = static_cast<double>(i);
        for (int quadrant = 0; quadrant < 4; quadrant++) {
            auto q_dbl = static_cast<double>(quadrant);
            test_components<FixedType>(i_dbl * pi_two + pi_half * q_dbl);
            test_components<FixedType>(i_dbl * pi_two + pi_half * q_dbl + pi_half / 2.);
        }
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_random_data<FixedType>(seed_seq);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_trigonometric_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_trigonometric_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_trigonometric_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
