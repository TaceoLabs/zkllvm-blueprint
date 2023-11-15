#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_tester_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/tester.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON = 0.001;

bool doubleEquals(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    return fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

template<typename FixedType, typename ComponentType>
void add_argmax_inner(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_x,
                      typename FixedType::value_type index_y, bool select_last_index) {
    BLUEPRINT_RELEASE_ASSERT(index_x < index_y);

    double x_f = x.to_double();
    double y_f = y.to_double();

    double expected_res_f;
    FixedType expected_res(0, FixedType::SCALE);
    typename FixedType::value_type expected_index;

    expected_res_f = y.to_double();

    if (select_last_index) {
        // We have to evaluate x > y
        expected_res_f = x_f > y_f ? x_f : y_f;
        expected_res = x > y ? x : y;
        expected_index = x_f > y_f ? index_x : index_y;
    } else {
        // We have to evaluate x >= y
        expected_res_f = x_f >= y_f ? x_f : y_f;
        expected_res = x >= y ? x : y;
        expected_index = x_f >= y_f ? index_x : index_y;
    }

    BLUEPRINT_RELEASE_ASSERT(doubleEquals(expected_res_f, expected_res.to_double(), EPSILON));

    std::vector<typename FixedType::value_type> inputs = {x.get_value(), y.get_value(), index_x};
    std::vector<typename FixedType::value_type> outputs = {expected_res.get_value(), expected_index};
    std::vector<typename FixedType::value_type> constants = {index_y, select_last_index ? 1 : 0};

    component.add_testcase(blueprint::components::FixedPointComponents::ARGMAX, inputs, outputs, constants);
}

template<typename FixedType, typename ComponentType>
void add_argmax(ComponentType &component, FixedType x, FixedType y, typename FixedType::value_type index_x,
                typename FixedType::value_type index_y) {
    if (index_y < index_x) {
        std::swap(index_x, index_y);
    }
    add_argmax_inner<FixedType, ComponentType>(component, x, y, index_x, index_y, true);
    add_argmax_inner<FixedType, ComponentType>(component, x, y, index_x, index_y, false);
}

static constexpr std::size_t INDEX_MAX = 1000;

template<typename FieldType, typename RngType>
FieldType generate_random_index(RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;

    distribution dist = distribution(0, INDEX_MAX);
    uint64_t x = dist(rng);
    return FieldType(x);
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

template<typename FixedType, typename ComponentType>
void test_components_unary_basic(ComponentType &component, int i) {
    FixedType x((int64_t)i);
}

template<typename FixedType, typename ComponentType>
void test_components_unary_positive(ComponentType &component, int i) {
    FixedType x((int64_t)i);
}

template<typename FixedType, typename ComponentType>
void test_components_binary_basic(ComponentType &component, int i, int j) {
    FixedType x((int64_t)i);
    FixedType y((int64_t)j);

    auto index_a = FixedType::value_type::one();
    auto index_b = typename FixedType::value_type(2);

    add_argmax<FixedType, ComponentType>(component, x, y, index_a, index_b);
}

template<typename FixedType, typename ComponentType, typename RngType>
void test_components_on_random_data(ComponentType &component, std::size_t i, RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);
    FixedType y(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);

    auto index_a = generate_random_index<typename FixedType::value_type>(rng);
    auto index_b = generate_random_index<typename FixedType::value_type>(rng);
    while (index_a == index_b) {
        index_b = generate_random_index<typename FixedType::value_type>(rng);
    }

    add_argmax<FixedType, ComponentType>(component, x, y, index_a, index_b);
}

template<typename FixedType, typename ComponentType, std::size_t RandomTestsAmount>
void field_operations_test_inner(ComponentType &component) {
    for (int i = -2; i < 3; i++) {
        // test_components_unary_basic<FixedType, ComponentType>(component, i);
        for (int j = -2; j < 3; j++) {
            test_components_binary_basic<FixedType, ComponentType>(component, i, j);
        }
    }

    // for (int i = 0; i < 5; i++) {
    //     test_components_unary_positive<FixedType, ComponentType>(component, i);
    // }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        //     test_components_on_bounded_random_data<FixedType, ComponentType>(component, seed_seq);
        test_components_on_random_data<FixedType, ComponentType>(component, i, seed_seq);
    }
}

template<typename FixedType, std::size_t RandomTestsAmount>
void field_operations_test() {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = blueprint::components::TESTER_MAX_CONSTANT_COLS;
    constexpr std::size_t SelectorColumns = 100;
    using ArithmetizationParams = crypto3::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns,
                                                                                   ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_tester<ArithmetizationType, BlueprintFieldType,
                                          nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    auto result_check = [](AssignmentType &assignment, typename component_type::result_type &real_res) {};

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    std::array<std::uint32_t, 0> public_list;
    std::array<std::uint32_t, ConstantColumns> constant_list;
    for (auto i = 0; i < ConstantColumns; i++) {
        constant_list[i] = i;
    }

    component_type component_instance(witness_list, constant_list, public_list, FixedType::M_1, FixedType::M_2);

    field_operations_test_inner<FixedType, component_type, RandomTestsAmount>(component_instance);

    typename component_type::input_type instance_input = {};
    std::vector<typename BlueprintFieldType::value_type> public_input = {};

    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input,
        crypto3::detail::connectedness_check_type::WEAK);
    // We do not have inputs/outputs so the weak check is sufficient
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_tester_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_tester_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_tester_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
