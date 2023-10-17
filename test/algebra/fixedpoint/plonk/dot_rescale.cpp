#define BOOST_TEST_MODULE blueprint_plonk_fixedpoint_dot_test

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
#include <nil/blueprint/components/algebra/fixedpoint/plonk/dot_rescale.hpp>

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
void test_components_on_random_data(std::size_t dots, RngType &rng) {
    std::vector<FixedType> x;
    std::vector<FixedType> y;
    x.reserve(dots);
    y.reserve(dots);

    for (auto i = 0; i < dots; i++) {
        x.push_back(FixedType(
            generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
            FixedType::SCALE));
        y.push_back(FixedType(
            generate_random_for_fixedpoint<typename FixedType::value_type>(FixedType::M_1, FixedType::M_2, rng),
            FixedType::SCALE));
    }

    // test_fixedpoint_dot<FixedType>(x, y);
}

template<typename FixedType>
void test_components(std::size_t dots) {
    std::vector<FixedType> x;
    std::vector<FixedType> y;
    x.reserve(dots);
    y.reserve(dots);

    for (auto i = 0; i < dots; i++) {
        x.push_back(FixedType((int64_t)i));
        y.push_back(FixedType((int64_t)i));
    }

    // test_fixedpoint_dot<FixedType>(x, y);
}

template<typename FixedType>
void field_operations_test() {
    for (std::size_t i = 1; i < 5; i++) {
        test_components<FixedType>(i);
    }

    boost::random::mt19937 seed_seq(0);
    for (std::size_t i = 0; i < 5; i++) {
        test_components_on_random_data<FixedType>(i, seed_seq);
    }
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_dot_test_vesta) {
    using field_type = typename crypto3::algebra::curves::vesta::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_dot_test_pallas) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_CASE(blueprint_plonk_fixedpoint_dot_test_bls12) {
    using field_type = typename crypto3::algebra::fields::bls12_fr<381>;
    field_operations_test<FixedPoint16_16<field_type>>();
    field_operations_test<FixedPoint32_32<field_type>>();
}

BOOST_AUTO_TEST_SUITE_END()
