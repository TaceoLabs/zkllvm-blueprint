#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TABLES_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TABLES_HPP

#include <cstdint>
#include <cmath>

#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType>
            class FixedPointTables {
                using value_type = typename BlueprintFieldType::value_type;
                using big_float = nil::crypto3::multiprecision::cpp_bin_float_double;

                static std::vector<value_type> fill_range_table();

                static std::vector<value_type> fill_exp_a_table(uint8_t m2);
                static std::vector<value_type> fill_exp_b_table(uint8_t m2);

            public:
                FixedPointTables() = delete;
                FixedPointTables(const FixedPointTables &) = delete;
                FixedPointTables &operator=(const FixedPointTables &) = delete;

                static constexpr uint32_t RangeLen = (1ULL << 16);
                static constexpr uint16_t ExpBScale = 16;
                static constexpr uint32_t ExpALen = 201;
                static constexpr uint32_t ExpBLen = (1ULL << ExpBScale);

                static const std::vector<value_type> &get_range_table();

                static const std::vector<value_type> &get_exp_a_16();
                static const std::vector<value_type> &get_exp_a_32();
                static const std::vector<value_type> &get_exp_b_16();
                static const std::vector<value_type> &get_exp_b_32();

                template<uint8_t M2>
                static constexpr uint16_t get_exp_scale();
                static value_type get_lowest_exp_input(uint8_t m2);
                static value_type get_highest_exp_input(uint8_t m2);
                // Highest to still get m2 + m1 limbs
                static value_type get_highest_valid_exp_input(uint8_t m1, uint8_t m2);
            };

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_range_table() {
                static std::vector<value_type> range = fill_range_table();
                return range;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_a_16() {
                static std::vector<value_type> exp_a = fill_exp_a_table(1);
                return exp_a;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_a_32() {
                static std::vector<value_type> exp_a = fill_exp_a_table(2);
                return exp_a;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_b_16() {
                static std::vector<value_type> exp_b = fill_exp_b_table(1);
                return exp_b;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_b_32() {
                static std::vector<value_type> exp_b = fill_exp_b_table(2);
                return exp_b;
            }

            template<typename BlueprintFieldType>
            std::vector<typename FixedPointTables<BlueprintFieldType>::value_type>
                FixedPointTables<BlueprintFieldType>::fill_range_table() {
                std::vector<value_type> range;
                range.reserve(RangeLen);
                for (auto i = 0; i < RangeLen; ++i) {
                    range.push_back(value_type(i));
                }
                return range;
            }

            template<typename BlueprintFieldType>
            std::vector<typename FixedPointTables<BlueprintFieldType>::value_type>
                FixedPointTables<BlueprintFieldType>::fill_exp_a_table(uint8_t m2) {
                BLUEPRINT_RELEASE_ASSERT(m2 == 1 || m2 == 2);
                std::vector<value_type> exp_a;
                exp_a.reserve(ExpALen);
                for (auto i = 0; i < ExpALen; ++i) {
                    big_float val_in = i - (int32_t)ExpALen / 2;
                    big_float val;
                    nil::crypto3::multiprecision::default_ops::eval_exp(val.backend(), val_in.backend());
                    val *= (1ULL << (16 * m2));
                    auto int_val = val.convert_to<nil::crypto3::multiprecision::cpp_int>();
                    auto field_val = value_type(int_val);
                    exp_a.push_back(field_val);
                }
                return exp_a;
            }

            template<typename BlueprintFieldType>
            std::vector<typename FixedPointTables<BlueprintFieldType>::value_type>
                FixedPointTables<BlueprintFieldType>::fill_exp_b_table(uint8_t m2) {
                BLUEPRINT_RELEASE_ASSERT(m2 == 1 || m2 == 2);
                std::vector<value_type> exp_b;
                exp_b.reserve(ExpBLen);
                for (auto i = 0; i < ExpBLen; ++i) {
                    double val = std::exp((double)i / ExpBLen);
                    val *= (1ULL << (16 * m2));
                    auto int_val = uint64_t(val);
                    auto field_val = value_type(int_val);
                    exp_b.push_back(field_val);
                }
                return exp_b;
            }

            template<typename BlueprintFieldType>
            template<uint8_t M2>
            constexpr uint16_t FixedPointTables<BlueprintFieldType>::get_exp_scale() {
                static_assert(M2 > 0 && M2 < 3, "Only allow one or two post-comma limbs");
                return M2 * (16 + ExpBScale);
            }

            template<typename BlueprintFieldType>
            typename FixedPointTables<BlueprintFieldType>::value_type
                FixedPointTables<BlueprintFieldType>::get_highest_exp_input(uint8_t m2) {
                uint64_t delta = 1ULL << 16;
                value_type res = ExpALen / 2;
                res = res * delta + ExpBLen - 1;
                if (m2 == 2) {
                    res = res * delta + ExpBLen - 1;
                }
                return res;
            }

            // Highest values which still produce a result with only m1+m2 limbs
            template<typename BlueprintFieldType>
            typename FixedPointTables<BlueprintFieldType>::value_type
                FixedPointTables<BlueprintFieldType>::get_highest_valid_exp_input(uint8_t m1, uint8_t m2) {
                if (m1 == 1 && m2 == 1) {
                    return 726818;
                } else if (m1 == 2 && m2 == 1) {
                    return 1453635;
                } else if (m1 == 1 && m2 == 2) {
                    return 47632809983;
                } else if (m1 == 2 && m2 == 2) {
                    return 95265488895;
                } else {
                    BLUEPRINT_RELEASE_ASSERT(false);
                    return 0;
                }
            }

            template<typename BlueprintFieldType>
            typename FixedPointTables<BlueprintFieldType>::value_type
                FixedPointTables<BlueprintFieldType>::get_lowest_exp_input(uint8_t m2) {
                uint64_t delta = 1ULL << 16;
                value_type res = ExpALen / 2;
                res = res * delta;
                if (m2 == 2) {
                    res = res * delta;
                }
                return -res;
            }

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
