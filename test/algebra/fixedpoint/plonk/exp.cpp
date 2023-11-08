#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_exp_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/exp.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/exp_ranged.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/plonk/tanh.hpp>

#include "../../../test_plonk_component.hpp"

using namespace nil;
using nil::blueprint::components::FixedPoint16_16;
using nil::blueprint::components::FixedPoint32_32;

static constexpr double EPSILON = 0.001;

bool doubleEquals(double a, double b, double epsilon) {
    // Essentially equal from
    // https://stackoverflow.com/questions/17333/how-do-you-compare-float-and-double-while-accounting-for-precision-loss
    // or just smaller epsilon
    return fabs(a - b) < epsilon || fabs(a - b) <= ((fabs(a) > fabs(b) ? fabs(b) : fabs(a)) * epsilon);
}

template<typename FixedType>
void test_fixedpoint_exp(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 6 + 2 * FixedType::M_2;
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

    using component_type = blueprint::components::
        fix_exp<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = exp(input.to_double());
    auto expected_res = input.exp();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point exp test: "
                  << "\n";
        std::cout << "input_f : " << input.to_double() << "\n";
        std::cout << "input   : " << input.get_value().data << "\n";
        std::cout << "expected: " << expected_res_f << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n\n";
            std::cout << "expected (float): " << expected_res_f << "\n";
            std::cout << "real (float)    : " << real_res_f << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(
        witness_list, std::array<std::uint32_t, 0>(), std::array<std::uint32_t, 0>(), FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_exp_ranged(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 16;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type =
        blueprint::components::fix_exp_ranged<ArithmetizationType,
                                              BlueprintFieldType,
                                              nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    auto max_exp = FixedType::max();
    auto max_exp_f = max_exp.to_double();

    double expected_res_f = exp(input.to_double());
    if (expected_res_f > max_exp_f) {
        expected_res_f = max_exp_f;
    }
    auto expected_res = input.exp(true);
    BLUEPRINT_RELEASE_ASSERT(expected_res <= max_exp);

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point exp ranged test: "
                  << "\n";
        std::cout << "input_f : " << input.to_double() << "\n";
        std::cout << "input   : " << input.get_value().data << "\n";
        std::cout << "expected: " << expected_res_f << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        std::vector<uint16_t> decomp;
        BLUEPRINT_RELEASE_ASSERT(!FixedType::helper::decompose(real_res_.get_value(), decomp));
        while (decomp.size() > 1 && decomp[decomp.size() - 1] == 0) {
            decomp.pop_back();
        }
        BLUEPRINT_RELEASE_ASSERT(decomp.size() <= FixedType::M_2 + FixedType::M_1);
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n\n";
            std::cout << "expected (float): " << expected_res_f << "\n";
            std::cout << "real (float)    : " << real_res_f << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(witness_list,
                                      std::array<std::uint32_t, 2>({0, 1}),
                                      std::array<std::uint32_t, 0>(),
                                      FixedType::M_1,
                                      FixedType::M_2);

    std::vector<typename BlueprintFieldType::value_type> public_input = {input.get_value()};
    nil::crypto3::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename FixedType>
void test_fixedpoint_tanh(FixedType input) {
    using BlueprintFieldType = typename FixedType::field_type;
    constexpr std::size_t WitnessColumns = 16;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 2;
    constexpr std::size_t SelectorColumns = 4;
    using ArithmetizationParams = crypto3::zk::snark::
        plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;
    using AssignmentType = nil::blueprint::assignment<ArithmetizationType>;

    using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;

    using component_type = blueprint::components::
        fix_tanh<ArithmetizationType, BlueprintFieldType, nil::blueprint::basic_non_native_policy<BlueprintFieldType>>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    double expected_res_f = tanh(input.to_double());
    auto expected_res = input.tanh();

    auto result_check = [&expected_res, &expected_res_f, input](AssignmentType &assignment,
                                                                typename component_type::result_type &real_res) {
        auto real_res_ = FixedType(var_value(assignment, real_res.output), FixedType::SCALE);
        double real_res_f = real_res_.to_double();
#ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "fixed_point tanh test: "
                  << "\n";
        std::cout << "input_f : " << input.to_double() << "\n";
        std::cout << "input   : " << input.get_value().data << "\n";
        std::cout << "expected: " << expected_res_f << "\n";
        std::cout << "real    : " << real_res_f << "\n\n";
#endif
        if (!doubleEquals(expected_res_f, real_res_f, EPSILON) || expected_res != real_res_) {
            std::cout << "expected        : " << expected_res.get_value().data << "\n";
            std::cout << "real            : " << real_res_.get_value().data << "\n\n";
            std::cout << "expected (float): " << expected_res_f << "\n";
            std::cout << "real (float)    : " << real_res_f << "\n\n";
            abort();
        }
    };

    std::vector<std::uint32_t> witness_list;
    witness_list.reserve(WitnessColumns);
    for (auto i = 0; i < WitnessColumns; i++) {
        witness_list.push_back(i);
    }
    // Is done by the manifest in a real circuit
    component_type component_instance(witness_list,
                                      std::array<std::uint32_t, 2>({0, 1}),
                                      std::array<std::uint32_t, 0>(),
                                      FixedType::M_1,
                                      FixedType::M_2);

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

constexpr static const std::size_t UPPER_BOUND = 6;

template<typename FieldType, typename RngType>
typename FieldType::value_type generate_bounded_random_for_fixedpoint(uint8_t m2, RngType &rng) {
    using distribution = boost::random::uniform_int_distribution<uint64_t>;
    using value_type = typename FieldType::value_type;

    distribution dist = distribution(0, UPPER_BOUND);
    uint64_t pre = dist(rng);
    distribution dist_ = distribution(0, (1ULL << (16 * m2)) - 1);
    uint64_t post = dist_(rng);
    distribution dist_bool = distribution(0, 1);
    bool sign = dist_bool(rng) == 1;

    if (sign) {
        return -value_type(pre << (16 * m2)) + post;
    } else {
        return value_type(pre << (16 * m2)) + post;
    }
}

template<typename FixedType, typename RngType>
void test_components_on_bounded_random_data(RngType &rng) {
    FixedType x(generate_bounded_random_for_fixedpoint<typename FixedType::field_type>(FixedType::M_2, rng),
                FixedType::SCALE);

    test_fixedpoint_exp<FixedType>(x);
    test_fixedpoint_exp_ranged<FixedType>(x);
    test_fixedpoint_tanh<FixedType>(x);
}

template<typename FixedType, typename RngType>
void test_components_on_random_data(RngType &rng) {
    FixedType x(generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
                FixedType::SCALE);

    test_fixedpoint_exp_ranged<FixedType>(x);
    test_fixedpoint_tanh<FixedType>(x);
}

template<typename FixedType>
void test_components(int i) {
    FixedType x((int64_t)i);

    test_fixedpoint_exp<FixedType>(x);
    test_fixedpoint_exp_ranged<FixedType>(x);
    test_fixedpoint_tanh<FixedType>(x);
}

template<typename FixedType, std::size_t RandomTestsAmount>
void field_operations_test() {
    for (int i = -2; i < 3; i++) {
        test_components<FixedType>(i);
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_bounded_random_data<FixedType>(seed_seq);
    }

    for (std::size_t i = 0; i < RandomTestsAmount; i++) {
        test_components_on_random_data<FixedType>(seed_seq);
    }
}

constexpr static const std::size_t random_tests_amount = 10;

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_exp_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_exp_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_exp_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>, random_tests_amount>();
    field_operations_test<FixedPoint32_32<field_type>, random_tests_amount>();
}

BOOST_AUTO_TEST_SUITE_END()
