//---------------------------------------------------------------------------//
// Copyright (c) 2018-2020 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//

#define BOOST_TEST_MODULE r1cs_ppzksnark_test

#include <boost/test/unit_test.hpp>

#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/fields/mnt4/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt4/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt4.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/fields/mnt6/base_field.hpp>
#include <nil/crypto3/algebra/fields/mnt6/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/mnt6.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/mnt6.hpp>

#include <nil/crypto3/algebra/random_element.hpp>


#include <nil/crypto3/zk/snark/components/basic_components.hpp>
#include <nil/crypto3/zk/snark/components/pairing/params/mnt4.hpp>
#include <nil/crypto3/zk/snark/components/pairing/params/mnt6.hpp>
#include <nil/crypto3/zk/snark/components/pairing/pairing_params.hpp>

#include <nil/crypto3/zk/snark/components/fields/fp2_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp3_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp4_components.hpp>
#include <nil/crypto3/zk/snark/components/fields/fp6_2over3_components.hpp>
#include <nil/crypto3/zk/snark/components/verifiers/r1cs_ppzksnark_verifier_component.hpp>
#include <nil/crypto3/zk/snark/proof_systems/ppzksnark/r1cs_ppzksnark.hpp>

#include "../weierstrass_miller_loop.hpp"

using namespace nil::crypto3::zk::snark;
using namespace nil::crypto3::algebra;

template<typename ppT_A, typename ppT_B>
void test_verifier() {
    typedef typename ppT_A::scalar_field_type FieldT_A;
    typedef typename ppT_B::scalar_field_type FieldT_B;

    const std::size_t num_constraints = 50;
    const std::size_t primary_input_size = 3;

    r1cs_example<FieldT_A> example =
        generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    BOOST_CHECK(example.primary_input.size() == primary_input_size);

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);
    const r1cs_ppzksnark_proof<ppT_A> pi =
        r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = r1cs_ppzksnark_verifier_strong_input_consistency<ppT_A>(keypair.vk, example.primary_input, pi);
    BOOST_CHECK(bit);

    const std::size_t elt_size = FieldT_A::size_in_bits();
    const std::size_t primary_input_size_in_bits = elt_size * primary_input_size;
    const std::size_t vk_size_in_bits =
        r1cs_ppzksnark_verification_key_variable<ppT_B>::size_in_bits(primary_input_size);

    blueprint<FieldT_B> bp;
    blueprint_variable_vector<FieldT_B> vk_bits;
    vk_bits.allocate(bp, vk_size_in_bits);

    blueprint_variable_vector<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(bp, primary_input_size_in_bits);

    r1cs_ppzksnark_proof_variable<ppT_B> proof(bp);

    r1cs_ppzksnark_verification_key_variable<ppT_B> vk(bp, vk_bits, primary_input_size);

    variable<FieldT_B> result;
    result.allocate(bp);

    r1cs_ppzksnark_verifier_component<ppT_B> verifier(bp, vk, primary_input_bits, elt_size, proof, result);

    proof.generate_r1cs_constraints();
    verifier.generate_r1cs_constraints();

    std::vector<bool> input_as_bits;
    for (const FieldT_A &el : example.primary_input) {
        std::vector<bool> v = algebra::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(bp, input_as_bits);

    vk.generate_r1cs_witness(keypair.vk);
    proof.generate_r1cs_witness(pi);
    verifier.generate_r1cs_witness();
    bp.val(result) = FieldT_B::one();

    std::cout << "positive test:\n" << std::endl;
    BOOST_CHECK(bp.is_satisfied());

    bp.val(primary_input_bits[0]) = FieldT_B::one() - bp.val(primary_input_bits[0]);
    verifier.generate_r1cs_witness();
    bp.val(result) = FieldT_B::one();

    std::cout << "negative test:" << std::endl;
    BOOST_CHECK(!bp.is_satisfied());
    std::cout << "number of constraints for verifier:" << bp.num_constraints() << std::endl;
}

template<typename ppT_A, typename ppT_B>
void test_hardcoded_verifier() {
    typedef typename ppT_A::scalar_field_type FieldT_A;
    typedef typename ppT_B::scalar_field_type FieldT_B;

    const std::size_t num_constraints = 50;
    const std::size_t primary_input_size = 3;

    r1cs_example<FieldT_A> example =
        generate_r1cs_example_with_field_input<FieldT_A>(num_constraints, primary_input_size);
    BOOST_CHECK(example.primary_input.size() == primary_input_size);

    BOOST_CHECK(example.constraint_system.is_satisfied(example.primary_input, example.auxiliary_input));
    const r1cs_ppzksnark_keypair<ppT_A> keypair = r1cs_ppzksnark_generator<ppT_A>(example.constraint_system);
    const r1cs_ppzksnark_proof<ppT_A> pi =
        r1cs_ppzksnark_prover<ppT_A>(keypair.pk, example.primary_input, example.auxiliary_input);
    bool bit = r1cs_ppzksnark_verifier_strong_input_consistency<ppT_A>(keypair.vk, example.primary_input, pi);
    BOOST_CHECK(bit);

    const std::size_t elt_size = FieldT_A::size_in_bits();
    const std::size_t primary_input_size_in_bits = elt_size * primary_input_size;

    blueprint<FieldT_B> bp;
    r1cs_ppzksnark_preprocessed_r1cs_ppzksnark_verification_key_variable<ppT_B> hardcoded_vk(bp, keypair.vk);
    blueprint_variable_vector<FieldT_B> primary_input_bits;
    primary_input_bits.allocate(bp, primary_input_size_in_bits);

    r1cs_ppzksnark_proof_variable<ppT_B> proof(bp);

    variable<FieldT_B> result;
    result.allocate(bp);

    r1cs_ppzksnark_online_verifier_component<ppT_B> online_verifier(bp, hardcoded_vk, primary_input_bits, elt_size,
                                                                    proof, result);

    proof.generate_r1cs_constraints();
    online_verifier.generate_r1cs_constraints();

    std::vector<bool> input_as_bits;
    for (const FieldT_A &el : example.primary_input) {
        std::vector<bool> v = algebra::convert_field_element_to_bit_vector<FieldT_A>(el, elt_size);
        input_as_bits.insert(input_as_bits.end(), v.begin(), v.end());
    }

    primary_input_bits.fill_with_bits(bp, input_as_bits);

    proof.generate_r1cs_witness(pi);
    online_verifier.generate_r1cs_witness();
    bp.val(result) = FieldT_B::one();

    printf("positive test:\n");
    BOOST_CHECK(bp.is_satisfied());

    bp.val(primary_input_bits[0]) = FieldT_B::one() - bp.val(primary_input_bits[0]);
    online_verifier.generate_r1cs_witness();
    bp.val(result) = FieldT_B::one();

    printf("negative test:\n");
    BOOST_CHECK(!bp.is_satisfied());
    std::cout << "number of constraints for verifier: " << bp.num_constraints();
}

template<typename FpExtT, template<class> class VarT, template<class> class MulT>
void test_mul() {
    typedef typename FpExtT::my_Fp FieldType;

    blueprint<FieldType> bp;
    VarT<FpExtT> x(bp);
    VarT<FpExtT> y(bp);
    VarT<FpExtT> xy(bp);
    MulT<FpExtT> mul(bp, x, y, xy);
    mul.generate_r1cs_constraints();

    for (size_t i = 0; i < 10; ++i) {
        const typename FpExtT::value_type x_val = algebra::random_element<FpExtT>();
        const typename FpExtT::value_type y_val = algebra::random_element<FpExtT>();
        x.generate_r1cs_witness(x_val);
        y.generate_r1cs_witness(y_val);
        mul.generate_r1cs_witness();
        const typename FpExtT::value_type res = xy.get_element();
        BOOST_CHECK(res == x_val * y_val);
        BOOST_CHECK(bp.is_satisfied());
    }
    std::cout << "number of constraints:" << bp.num_constraints() << std::endl;
}

template<typename FpExtT, template<class> class VarT, template<class> class SqrT>
void test_sqr() {
    typedef typename FpExtT::my_Fp FieldType;

    blueprint<FieldType> bp;
    VarT<FpExtT> x(bp);
    VarT<FpExtT> xsq(bp);
    SqrT<FpExtT> sqr(bp, x, xsq);
    sqr.generate_r1cs_constraints();

    for (size_t i = 0; i < 10; ++i) {
        const typename FpExtT::value_type x_val = algebra::random_element<FpExtT>();
        x.generate_r1cs_witness(x_val);
        sqr.generate_r1cs_witness();
        const typename FpExtT::value_type res = xsq.get_element();
        BOOST_CHECK(res == x_val.squared());
        BOOST_CHECK(bp.is_satisfied());
    }
    std::cout << "number of constraints: " << bp.num_constraints() << std::endl;
}

template<typename CurveType, template<class> class VarT, template<class> class CycloSqrT>
void test_cyclotomic_sqr() {
    typedef algebra::Fqk<CurveType> FpExtT;
    typedef typename FpExtT::my_Fp FieldType;

    blueprint<FieldType> bp;
    VarT<FpExtT> x(bp);
    VarT<FpExtT> xsq(bp);
    CycloSqrT<FpExtT> sqr(bp, x, xsq);
    sqr.generate_r1cs_constraints();

    for (size_t i = 0; i < 10; ++i) {
        FpExtT::value_type x_val = algebra::random_element<FpExtT>();
        x_val = final_exponentiation<CurveType>(x_val);

        x.generate_r1cs_witness(x_val);
        sqr.generate_r1cs_witness();
        const typename FpExtT::value_type res = xsq.get_element();
        BOOST_CHECK(res == x_val.squared());
        BOOST_CHECK(bp.is_satisfied());
    }
    std::cout << "number of constraints: " << bp.num_constraints() << std::endl;
}

template<typename FpExtT, template<class> class VarT>
void test_Frobenius() {
    typedef typename FpExtT::my_Fp FieldType;

    for (size_t i = 0; i < 100; ++i) {
        blueprint<FieldType> bp;
        VarT<FpExtT> x(bp);
        VarT<FpExtT> x_frob = x.Frobenius_map(i);

        const typename FpExtT::value_type x_val = algebra::random_element<FpExtT>();
        x.generate_r1cs_witness(x_val);
        x_frob.evaluate();
        const typename FpExtT::value_type res = x_frob.get_element();
        BOOST_CHECK(res == x_val.Frobenius_map(i));
        BOOST_CHECK(bp.is_satisfied());
    }
}

template<typename CurveType>
void test_full_pair() {
    typedef typename CurveType::scalar_field_type FieldType;
    typedef typename pairing::CurveType::pairing::pair_curve_type::pairing pairing_policy;

    blueprint<FieldType> bp;
    pairing::CurveType::pairing::pair_curve_type::g1_type::value_type P_val =
        algebra::random_element<pairing::CurveType::pairing::pair_curve_type::scalar_field_type>() *
        pairing::CurveType::pairing::pair_curve_type::g1_type::value_type::one();
    pairing::CurveType::pairing::pair_curve_type::g2_type::value_type Q_val =
        algebra::random_element<pairing::CurveType::pairing::pair_curve_type::scalar_field_type>() *
        pairing::CurveType::pairing::pair_curve_type::g2_type::value_type::one();

    g1_variable<CurveType> P(bp);
    g2_variable<CurveType> Q(bp);
    g1_precomputation<CurveType> prec_P;
    g2_precomputation<CurveType> prec_Q;

    precompute_G1_component<CurveType> compute_prec_P(bp, P, prec_P);
    precompute_G2_component<CurveType> compute_prec_Q(bp, Q, prec_Q);

    Fqk_variable<CurveType> miller_result(bp);
    mnt_miller_loop_component<CurveType> miller(bp, prec_P, prec_Q, miller_result);
    variable<FieldType> result_is_one;
    result_is_one.allocate(bp);
    final_exp_component<CurveType> finexp(bp, miller_result, result_is_one);

    compute_prec_P.generate_r1cs_constraints();
    compute_prec_Q.generate_r1cs_constraints();
    miller.generate_r1cs_constraints();
    finexp.generate_r1cs_constraints();

    P.generate_r1cs_witness(P_val);
    compute_prec_P.generate_r1cs_witness();
    Q.generate_r1cs_witness(Q_val);
    compute_prec_Q.generate_r1cs_witness();
    miller.generate_r1cs_witness();
    finexp.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    typename pairing_policy::affine_ate_g1_precomp native_prec_P = pairing_policy::affine_ate_precompute_g1(P_val);
    typename pairing_policy::affine_ate_g2_precomp native_prec_Q = pairing_policy::affine_ate_precompute_g2(Q_val);
    typename pairing_policy::Fqk native_miller_result =
        pairing_policy::affine_ate_miller_loop(native_prec_P, native_prec_Q);

    typename pairing_policy::Fqk native_finexp_result = pairing_policy::final_exponentiation(native_miller_result);
    printf("Must match:\n");
    finexp.result->get_element().print();
    native_finexp_result.print();

    BOOST_CHECK(finexp.result->get_element() == native_finexp_result);

    std::cout << "number of constraints for full pairing: " << bp.num_constraints() << std::endl;
}

template<typename CurveType>
void test_full_precomputed_pair() {
    typedef typename CurveType::scalar_field_type FieldType;
    typedef typename pairing::CurveType::pairing::pair_curve_type::pairing pairing_policy;

    blueprint<FieldType> bp;
    pairing::CurveType::pairing::pair_curve_type::g1_type::value_type P_val =
        algebra::random_element<pairing::CurveType::pairing::pair_curve_type::scalar_field_type>() *
        pairing::CurveType::pairing::pair_curve_type::g1_type::value_type::one();
    pairing::CurveType::pairing::pair_curve_type::g2_type::value_type Q_val =
        algebra::random_element<pairing::CurveType::pairing::pair_curve_type::scalar_field_type>() *
        pairing::CurveType::pairing::pair_curve_type::g2_type::value_type::one();

    g1_precomputation<CurveType> prec_P(bp, P_val);
    g2_precomputation<CurveType> prec_Q(bp, Q_val);

    Fqk_variable<CurveType> miller_result(bp);
    mnt_miller_loop_component<CurveType> miller(bp, prec_P, prec_Q, miller_result);
    variable<FieldType> result_is_one;
    result_is_one.allocate(bp);
    final_exp_component<CurveType> finexp(bp, miller_result, result_is_one);

    miller.generate_r1cs_constraints();
    finexp.generate_r1cs_constraints();

    miller.generate_r1cs_witness();
    finexp.generate_r1cs_witness();
    BOOST_CHECK(bp.is_satisfied());

    typename pairing_policy::affine_ate_g1_precomp native_prec_P = pairing_policy::affine_ate_precompute_g1(P_val);
    typename pairing_policy::affine_ate_g2_precomp native_prec_Q = pairing_policy::affine_ate_precompute_g2(Q_val);
    typename pairing_policy::Fqk native_miller_result =
        pairing_policy::affine_ate_miller_loop(native_prec_P, native_prec_Q);

    typename pairing_policy::Fqk native_finexp_result = pairing_policy::final_exponentiation(native_miller_result);
    printf("Must match:\n");
    finexp.result->get_element().print();
    native_finexp_result.print();

    BOOST_CHECK(finexp.result->get_element() == native_finexp_result);

    std::cout << "number of constraints for full precomputed pairing: " << bp.num_constraints() << std::endl;
}

BOOST_AUTO_TEST_SUITE(benes_components_test_suite)

BOOST_AUTO_TEST_CASE(benes_components_test) {

    test_mul<algebra::mnt4_Fq2, Fp2_variable, Fp2_mul_component>();
    test_sqr<algebra::mnt4_Fq2, Fp2_variable, Fp2_sqr_component>();

    test_mul<algebra::mnt4_Fq4, Fp4_variable, Fp4_mul_component>();
    test_sqr<algebra::mnt4_Fq4, Fp4_variable, Fp4_sqr_component>();
    test_cyclotomic_sqr<curves::mnt4, Fp4_variable, Fp4_cyclotomic_sqr_component>();
    test_exponentiation_component<algebra::mnt4_Fq4, Fp4_variable, Fp4_mul_component, Fp4_sqr_component,
                                  algebra::mnt4_q_limbs>(algebra::mnt4_final_exponent_last_chunk_abs_of_w0);
    test_Frobenius<algebra::mnt4_Fq4, Fp4_variable>();

    test_mul<algebra::mnt6_Fq3, Fp3_variable, Fp3_mul_component>();
    test_sqr<algebra::mnt6_Fq3, Fp3_variable, Fp3_sqr_component>();

    test_mul<algebra::mnt6_Fq6, Fp6_2over3_variable, Fp6_2over3_mul_component>();
    test_sqr<algebra::mnt6_Fq6, Fp6_2over3_variable, Fp6_2over3_sqr_component>();
    test_cyclotomic_sqr<curves::mnt6, Fp6_2over3_variable, Fp6_2over3_cyclotomic_sqr_component>();
    test_exponentiation_component<algebra::mnt6_Fq6, Fp6_2over3_variable, Fp6_2over3_mul_component, Fp6_2over3_sqr_component,
                                  algebra::mnt6_q_limbs>(algebra::mnt6_final_exponent_last_chunk_abs_of_w0);
    test_Frobenius<algebra::mnt6_Fq6, Fp6_2over3_variable>();

    test_G2_checker_component<curves::mnt4>();
    test_G2_checker_component<curves::mnt6>();

    test_g1_variable_precomp<curves::mnt4>();
    test_g1_variable_precomp<curves::mnt6>();

    test_g2_variable_precomp<curves::mnt4>();
    test_g2_variable_precomp<curves::mnt6>();

    test_mnt_miller_loop<curves::mnt4>();
    test_mnt_miller_loop<curves::mnt6>();

    test_mnt_e_over_e_miller_loop<curves::mnt4>();
    test_mnt_e_over_e_miller_loop<curves::mnt6>();

    test_mnt_e_times_e_over_e_miller_loop<curves::mnt4>();
    test_mnt_e_times_e_over_e_miller_loop<curves::mnt6>();

    test_full_pairing<curves::mnt4>();
    test_full_pairing<curves::mnt6>();

    test_full_precomputed_pairing<curves::mnt4>();
    test_full_precomputed_pairing<curves::mnt6>();

    test_verifier<curves::mnt4, curves::mnt6>();
    test_verifier<curves::mnt6, curves::mnt4>();

    test_hardcoded_verifier<curves::mnt4, curves::mnt6>();
    test_hardcoded_verifier<curves::mnt6, curves::mnt4>();
}

BOOST_AUTO_TEST_SUITE_END()
