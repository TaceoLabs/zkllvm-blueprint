#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP

#include <cstdint>
#include <cmath>

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
            class FixedPoint {
                using value_type = typename BlueprintFieldType::value_type;
                using modular_backend = typename BlueprintFieldType::modular_backend;

                // TACEO_TODO something along the lines of the following for template asserts
                //  static_assert(MinBits, "number of bits should be defined");
                // static_assert(is_fixed_precision<Backend>::value, "fixed precision backend should be used");

            private:
                // I need a field element to deal with larger scales, such as the one as output from exp
                value_type value;
                uint16_t scale;

            public:
                // TACEO_TODO this is hardcoded here
                static constexpr uint16_t SCALE = 16;
                static constexpr uint64_t DELTA = (1 << SCALE);
                static constexpr uint64_t DELTA_2 = (1 << (SCALE - 1));
                static constexpr value_type P_HALF = BlueprintFieldType::modulus / 2;

                static DivMod<BlueprintFieldType> rescale(const value_type &);

                // Initiliaze from real values
                FixedPoint(double x);
                FixedPoint(int64_t x);
                // Initialize from Fixedpoint representation
                FixedPoint(const value_type &value, uint16_t scale);
                virtual ~FixedPoint() = default;
                FixedPoint(const FixedPoint &) = default;
                FixedPoint &operator=(const FixedPoint &) = default;

                FixedPoint operator+(const FixedPoint &other);
                double to_double() const;
                value_type get_value() const {
                    return value;
                }
                uint16_t get_scale() const {
                    return scale;
                }

                // Transforms from/to montgomery representation
                static modular_backend field_to_backend(const value_type &);
                static value_type backend_to_field(const modular_backend &);

                static bool abs(value_type &);    // Returns true if sign was changed
            };

            template<typename BlueprintFieldType>
            typename FixedPoint<BlueprintFieldType>::modular_backend
                FixedPoint<BlueprintFieldType>::field_to_backend(const value_type &x) {
                modular_backend out;
                BlueprintFieldType::modulus_params.adjust_regular(out, x.data.backend().base_data());
                return out;
            }

            template<typename BlueprintFieldType>
            typename FixedPoint<BlueprintFieldType>::value_type
                FixedPoint<BlueprintFieldType>::backend_to_field(const modular_backend &x) {
                value_type out;
                out.data.backend().base_data() = x;
                BlueprintFieldType::modulus_params.adjust_modular(out.data.backend().base_data());
                return out;
            }

            template<typename BlueprintFieldType>
            bool FixedPoint<BlueprintFieldType>::abs(value_type &x) {
                bool sign = false;
                if (x > P_HALF) {
                    x = -x;
                    sign = true;
                }
                return sign;
            }

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::FixedPoint(double x) : scale(SCALE) {
                if (x < 0) {
                    value = -value_type(static_cast<int64_t>(-x * DELTA));
                } else {
                    value = static_cast<int64_t>(x * DELTA);
                }
            }

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::FixedPoint(int64_t x) : scale(SCALE) {
                if (x < 0) {
                    value = -value_type(-x * DELTA);
                } else {
                    value = x * DELTA;
                }
            }

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::FixedPoint(const value_type &value, uint16_t scale) :
                value(value), scale(SCALE) {};

            // res.quotient = Round(val / Delta)
            // remainder required for proof
            template<typename BlueprintFieldType>
            DivMod<BlueprintFieldType>
                FixedPoint<BlueprintFieldType>::rescale(const typename BlueprintFieldType::value_type &val) {
                DivMod<BlueprintFieldType> res;

                modular_backend delta;
                delta.limbs()[0] = DELTA;
                auto tmp = val;    // No + Delta_2 since eval_divide seems to round
                bool sign = abs(tmp);
                modular_backend out = field_to_backend(tmp);

                modular_backend out_;
                eval_divide(out_, out, delta);    // Seems to already include rounding

                res.quotient = backend_to_field(out_);
                if (sign) {
                    res.quotient = -res.quotient;
                }
                // // res.remainder = (val + DELTA_2) % DELTA;
                res.remainder = (val + DELTA_2) - res.quotient * DELTA;
                if (res.remainder >= DELTA) {
                    std::cout << "Remainder is too large\n";
                    abort();
                }
                return res;
            }

            template<typename BlueprintFieldType>
            double FixedPoint<BlueprintFieldType>::to_double() const {
                auto tmp = value;
                bool sign = abs(tmp);

                modular_backend out = field_to_backend(tmp);
                if (out.sign()) {
                    std::cout << "Sign in a field is always positive\n";
                    abort();
                }
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

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>
                FixedPoint<BlueprintFieldType>::operator+(const FixedPoint<BlueprintFieldType> &other) {
                if (scale != other.scale) {
                    abort();
                }
                return FixedPoint<BlueprintFieldType>(value + other.value, scale);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
