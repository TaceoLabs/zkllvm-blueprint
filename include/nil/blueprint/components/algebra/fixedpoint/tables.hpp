#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TABLES_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_TABLES_HPP

#include <cstdint>
#include <cmath>

#include <nil/crypto3/multiprecision/cpp_bin_float.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            class FixedPointTables {
                using value_type = typename BlueprintFieldType::value_type;
                using big_float = nil::crypto3::multiprecision::cpp_bin_float_double;

                static std::vector<value_type> fill_exp_a_table();
                static std::vector<value_type> fill_exp_b_table();

            public:
                FixedPointTables() = delete;
                FixedPointTables(const FixedPointTables &) = delete;
                FixedPointTables &operator=(const FixedPointTables &) = delete;

                static constexpr uint16_t ExpAScale = 128;
                static constexpr uint16_t ExpBScale = 32;

                static constexpr uint32_t ExpALen = 151;
                static constexpr uint32_t ExpBLen = (1 << 16);

                static const std::vector<value_type> &get_exp_a();
                static const std::vector<value_type> &get_exp_b();
            };

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            const std::vector<typename FixedPointTables<BlueprintFieldType, M1, M2>::value_type> &
                FixedPointTables<BlueprintFieldType, M1, M2>::get_exp_a() {
                static std::vector<value_type> exp_a = fill_exp_a_table();
                return exp_a;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            const std::vector<typename FixedPointTables<BlueprintFieldType, M1, M2>::value_type> &
                FixedPointTables<BlueprintFieldType, M1, M2>::get_exp_b() {
                static std::vector<value_type> exp_b = fill_exp_b_table();
                return exp_b;
            }

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            std::vector<typename FixedPointTables<BlueprintFieldType, M1, M2>::value_type>
                FixedPointTables<BlueprintFieldType, M1, M2>::fill_exp_a_table() {
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

            template<typename BlueprintFieldType, uint8_t M1, uint8_t M2>
            std::vector<typename FixedPointTables<BlueprintFieldType, M1, M2>::value_type>
                FixedPointTables<BlueprintFieldType, M1, M2>::fill_exp_b_table() {
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

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_HPP
