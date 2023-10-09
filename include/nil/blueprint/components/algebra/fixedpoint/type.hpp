#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP

#include <cstdint>

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

            private:
                value_type value;
                uint16_t scale;

            public:
                // TACEO_TODO this is hardcoded here
                static constexpr uint16_t SCALE = 16;
                static constexpr uint64_t DELTA = (1 << SCALE);
                static constexpr uint64_t DELTA_2 = (1 << (SCALE - 1));

                static DivMod<BlueprintFieldType> rescale(const value_type &);

                // Initiliaze from real values
                FixedPoint(double x);
                FixedPoint(uint64_t x);
                // Initialize from Fixedpoint representation
                FixedPoint(const value_type &value, uint16_t scale);
                virtual ~FixedPoint() = default;
                FixedPoint(const FixedPoint &) = default;
                FixedPoint &operator=(const FixedPoint &) = default;

                FixedPoint operator+(const FixedPoint &other);
                double to_double() const;
                value_type get_value() const;
                uint16_t get_scale() const;
            };

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::FixedPoint(double x) : scale(SCALE) {
                value = x * DELTA;
            }

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::FixedPoint(uint64_t x) : scale(SCALE) {
                value = x * DELTA;
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
                res.quotient = (val + DELTA_2) / DELTA;
                // res.remainder = (val + DELTA_2) % DELTA;
                res.remainder = (val + DELTA_2) - res.quotient * DELTA;
                return res;
            }

            template<typename BluePrintFieldType>
            double FixedPoint<BluePrintFieldType>::to_double() const {
                // TACEO_TODO This does not work
                double val = value;
                return val / ((uint64_t)1 << scale);
            }

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>
                FixedPoint<BlueprintFieldType>::operator+(const FixedPoint<BlueprintFieldType> &other) {
                if (scale != other.scale) {
                    abort();
                }
                return FixedPoint<BlueprintFieldType>(value + other.value, scale);
            }

            template<typename BlueprintFieldType>
            typename BlueprintFieldType::value_type FixedPoint<BlueprintFieldType>::get_value() const {
                return value;
            }

            template<typename BlueprintFieldType>
            uint16_t FixedPoint<BlueprintFieldType>::get_scale() const {
                return scale;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
