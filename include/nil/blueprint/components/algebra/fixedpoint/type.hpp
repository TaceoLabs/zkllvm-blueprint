#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            class FixedPoint {
                typedef value_type = typename BlueprintFieldType::value_type;

            private:
                value_type value;
                uint16_t scale;

            public:
                // TACEO_TODO this is hardcoded here
                static constexpr uint16_t SCALE = 16;
                static constexpr uint64_t DELTA = (1 << SCALE);

                FixedPoint(double x);
                FixedPoint(const value_type &value, uint16_t scale);
                virtual ~FixedPoint() = default;
                FixedPoint(const FixedPoint &) = default;
                FixedPoint &operator=(const FixedPoint &) = default;
                FixedPoint(const FixedPoint &&) = default;

                double to_double() const;
            };

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::Fixedpoint(double x) : scale(SCALE) {
                value = x * DELTA;
            }

            template<typename BlueprintFieldType>
            FixedPoint<BlueprintFieldType>::Fixedpoint(const value_type &value, uint16_t scale) :
                value(value), scale(SCALE) {};

            template<typename BluePrintFieldType>
            double FixedPoint<BlueprintFieldType>::to_double() const {
                double val = value;
                return val / ((uint64_t)1 << scale);
            }

            template<typename BluePrintFieldType>
            FixedPoint<BlueprintFieldType> operator+(const FixedPoint<BlueprintFieldType> &other) {
                assert(scale == other.scale);
                return FixedPoint<BlueprintFieldType>(value + other.value, scale);
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
