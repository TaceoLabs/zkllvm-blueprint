#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP

#include <cstdint>
#include <cmath>

#include <nil/blueprint/assert.hpp>
#include <nil/crypto3/multiprecision/cpp_int/divide.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            struct DivMod {
                using value_type = typename BlueprintFieldType::value_type;
                value_type quotient;
                value_type remainder;
            };

            template<typename BlueprintFieldType>
            class FixedPointHelper {
            public:
                using field_type = BlueprintFieldType;
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;

                static constexpr value_type P_HALF = BlueprintFieldType::modulus / 2;

                // M2 is the number of post-comma 16-bit limbs
                static DivMod<BlueprintFieldType> round_div_mod(const value_type &, uint64_t mod);

                // Transforms from/to montgomery representation
                static modular_backend field_to_backend(const value_type &);
                static value_type backend_to_field(const modular_backend &);

                static bool abs(value_type &);    // Returns true if sign was changed
                static bool decompose(const value_type &, std::vector<uint16_t> &);    // Returns sign
            };

            // FieldType is the representation of the proof system, whereas M1 is the number of pre-comma 16-bit limbs
            // and M2 the number of post-comma 16-bit limbs
            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            class FixedPoint {

                static_assert(M1 > 0 && M1 < 3, "Only allow one or two pre-comma linbs");
                static_assert(M2 > 0 && M2 < 3, "Only allow one or two post-comma linbs");

            public:
                using helper = FixedPointHelper<BlueprintFieldType>;
                using field_type = BlueprintFieldType;
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;

            private:
                // I need a field element to deal with larger scales, such as the one as output from exp
                value_type value;
                uint16_t scale;

            public:
                static constexpr uint8_t M_1 = M1;
                static constexpr uint8_t M_2 = M1;
                static constexpr uint16_t SCALE = 16 * M2;
                static constexpr uint64_t DELTA = (1ULL << SCALE);

                // Initiliaze from real values
                FixedPoint(double x);
                FixedPoint(int64_t x);
                // Initialize from Fixedpoint representation
                FixedPoint(const value_type &value, uint16_t scale);
                virtual ~FixedPoint() = default;
                FixedPoint(const FixedPoint &) = default;
                FixedPoint &operator=(const FixedPoint &) = default;

                bool operator==(const FixedPoint &other);
                bool operator!=(const FixedPoint &other);

                FixedPoint operator+(const FixedPoint &other);
                FixedPoint operator-(const FixedPoint &other);
                FixedPoint operator*(const FixedPoint &other);

                double to_double() const;
                value_type get_value() const {
                    return value;
                }
                uint16_t get_scale() const {
                    return scale;
                }
            };

            // TypeDefs
            template<typename BlueprintFieldType>
            using FixedPoint16_16 = FixedPoint<BlueprintFieldType, 1, 1>;
            template<typename BlueprintFieldType>
            using FixedPoint32_32 = FixedPoint<BlueprintFieldType, 2, 2>;

            template<typename BlueprintFieldType>
            typename FixedPointHelper<BlueprintFieldType>::modular_backend
                FixedPointHelper<BlueprintFieldType>::field_to_backend(const value_type &x) {
                modular_backend out;
                BlueprintFieldType::modulus_params.adjust_regular(out, x.data.backend().base_data());
                return out;
            }

            template<typename BlueprintFieldType>
            typename FixedPointHelper<BlueprintFieldType>::value_type
                FixedPointHelper<BlueprintFieldType>::backend_to_field(const modular_backend &x) {
                value_type out;
                out.data.backend().base_data() = x;
                BlueprintFieldType::modulus_params.adjust_modular(out.data.backend().base_data());
                return out;
            }

            template<typename BlueprintFieldType>
            bool FixedPointHelper<BlueprintFieldType>::abs(value_type &x) {
                bool sign = false;
                if (x > P_HALF) {
                    x = -x;
                    sign = true;
                }
                return sign;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(double x) : scale(SCALE) {
                if (x < 0) {
                    value = -value_type(static_cast<int64_t>(-x * DELTA));
                } else {
                    value = static_cast<int64_t>(x * DELTA);
                }
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(int64_t x) : scale(SCALE) {
                if (x < 0) {
                    value = -value_type(-x * DELTA);
                } else {
                    value = x * DELTA;
                }
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>::FixedPoint(const value_type &value, uint16_t scale) :
                value(value), scale(SCALE) {};

            template<typename BlueprintFieldType>
            bool FixedPointHelper<BlueprintFieldType>::decompose(const value_type &inp, std::vector<uint16_t> &output) {
                auto tmp_ = inp;
                bool sign = abs(tmp_);

                output.clear();

                auto tmp = field_to_backend(tmp_);
                for (auto i = 0; i < tmp.size(); i++) {
                    for (auto j = 0; j < 4; j++) {
                        output.push_back(tmp.limbs()[i] & 0xFFFF);
                        tmp.limbs()[i] >>= 16;
                    }
                }

                return sign;
            }

            // res.quotient = Round(val / Delta)
            // remainder required for proof
            template<typename BlueprintFieldType>
            DivMod<BlueprintFieldType>
                FixedPointHelper<BlueprintFieldType>::round_div_mod(const typename BlueprintFieldType::value_type &val,
                                                                    uint64_t mod) {
                DivMod<BlueprintFieldType> res;

                modular_backend mod_;
                mod_.limbs()[0] = mod;
                auto tmp = val + (mod >> 1);
                bool sign = abs(tmp);
                modular_backend out = field_to_backend(tmp);

                modular_backend out_;
                eval_divide(out_, out, mod_);

                res.quotient = backend_to_field(out_);
                if (sign) {
                    res.quotient = -res.quotient;
                }
                // res.remainder = (val + mod/2) % mod;
                res.remainder = val + (mod >> 1) - res.quotient * mod;
                if (res.remainder > P_HALF) {
                    // negative? artifact of eval_divide?
                    res.remainder += mod;
                    res.quotient -= 1;
                }
                BLUEPRINT_RELEASE_ASSERT(res.remainder < mod);
                return res;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            double FixedPoint<BlueprintFieldType, M1, M2>::to_double() const {
                auto tmp = value;
                bool sign = helper::abs(tmp);

                modular_backend out = helper::field_to_backend(tmp);
                BLUEPRINT_RELEASE_ASSERT(!out.sign());
                auto limbs_ptr = out.limbs();
                auto size = out.size();

                double val = 0;
                double pow64 = pow(2., 64);
                for (auto i = 0; i < size; i++) {
                    val *= pow64;
                    val += (double)(limbs_ptr[size - 1 - i]);
                }
                if (sign) {
                    val = -val;
                }
                return val / pow(2., scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator==(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) {
                return (value == other.value) && (scale == other.scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            bool FixedPoint<BlueprintFieldType, M1, M2>::operator!=(
                const FixedPoint<BlueprintFieldType, M1, M2> &other) {
                return (value != other.value) || (scale != other.scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>
                FixedPoint<BlueprintFieldType, M1, M2>::operator+(const FixedPoint<BlueprintFieldType, M1, M2> &other) {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                return FixedPoint(value + other.value, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>
                FixedPoint<BlueprintFieldType, M1, M2>::operator-(const FixedPoint<BlueprintFieldType, M1, M2> &other) {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                return FixedPoint(value - other.value, scale);
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            FixedPoint<BlueprintFieldType, M1, M2>
                FixedPoint<BlueprintFieldType, M1, M2>::operator*(const FixedPoint<BlueprintFieldType, M1, M2> &other) {
                BLUEPRINT_RELEASE_ASSERT(scale == other.scale);
                auto mul = value * other.value;
                auto divmod = helper::round_div_mod(mul, 1ULL << scale);
                return FixedPoint(divmod.quotient, scale);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
