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

                static std::vector<value_type> fill_exp_a_table();
                static std::vector<value_type> fill_exp_b_table();
                static std::vector<value_type> fill_exp_c_table();

            public:
                FixedPointTables() = delete;
                FixedPointTables(const FixedPointTables &) = delete;
                FixedPointTables &operator=(const FixedPointTables &) = delete;

                static constexpr uint16_t ExpAScale = 128;
                static constexpr uint16_t ExpBScale = 16;
                static constexpr uint16_t ExpCScale = 16;

                static constexpr uint32_t ExpALen = 151;
                static constexpr uint32_t ExpBLen = (1 << 16);
                static constexpr uint32_t ExpCLen = (1 << 16);

                static const std::vector<value_type> &get_exp_a();
                static const std::vector<value_type> &get_exp_b();
                static const std::vector<value_type> &get_exp_c();

                template<uint8_t M2>
                static constexpr uint16_t get_exp_scale();
            };

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_a() {
                static std::vector<value_type> exp_a = fill_exp_a_table();
                return exp_a;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_b() {
                static std::vector<value_type> exp_b = fill_exp_b_table();
                return exp_b;
            }

            template<typename BlueprintFieldType>
            const std::vector<typename FixedPointTables<BlueprintFieldType>::value_type> &
                FixedPointTables<BlueprintFieldType>::get_exp_c() {
                static std::vector<value_type> exp_c = fill_exp_c_table();
                return exp_c;
            }

            template<typename BlueprintFieldType>
            std::vector<typename FixedPointTables<BlueprintFieldType>::value_type>
                FixedPointTables<BlueprintFieldType>::fill_exp_a_table() {
                std::vector<value_type> exp_a;
                exp_a.reserve(ExpALen);
                for (auto i = 0; i < ExpALen; ++i) {
                    big_float val = std::exp(i - (int32_t)ExpALen / 2);
                    val *= pow(2., ExpAScale);
                    auto int_val = val.convert_to<nil::crypto3::multiprecision::cpp_int>();
                    auto field_val = value_type(int_val);
                    exp_a.push_back(field_val);
                }
                return exp_a;
            }

            template<typename BlueprintFieldType>
            std::vector<typename FixedPointTables<BlueprintFieldType>::value_type>
                FixedPointTables<BlueprintFieldType>::fill_exp_b_table() {
                std::vector<value_type> exp_b;
                exp_b.reserve(ExpBLen);
                for (auto i = 0; i < ExpBLen; ++i) {
                    double val = std::exp((double)i / ExpBLen);
                    val *= pow(2., ExpBScale);
                    auto int_val = uint64_t(val);
                    auto field_val = value_type(int_val);
                    exp_b.push_back(field_val);
                }
                return exp_b;
            }

            template<typename BlueprintFieldType>
            std::vector<typename FixedPointTables<BlueprintFieldType>::value_type>
                FixedPointTables<BlueprintFieldType>::fill_exp_c_table() {
                std::vector<value_type> exp_c;
                exp_c.reserve(ExpCLen);
                for (auto i = 0; i < ExpCLen; ++i) {
                    double val = std::exp((double)i / ((uint64_t)ExpBLen * ExpCLen));
                    val *= pow(2., ExpCScale);
                    auto int_val = uint64_t(val);
                    auto field_val = value_type(int_val);
                    exp_c.push_back(field_val);
                }
                return exp_c;
            }

            template<typename BlueprintFieldType>
            template<uint8_t M2>
            constexpr uint16_t FixedPointTables<BlueprintFieldType>::get_exp_scale() {
                static_assert(M2 > 0 && M2 < 3, "Only allow one or two post-comma linbs");
                if (M2 == 1) {
                    return ExpAScale + ExpBScale;
                } else {
                    return ExpAScale + ExpBScale + ExpCScale;
                }
            }

        }    // namespace components
    }    // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
