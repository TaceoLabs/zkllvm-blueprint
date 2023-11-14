#ifndef CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_TABLE_HPP
#define CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_TABLE_HPP

#include <string>
#include <map>

#include <nil/crypto3/zk/snark/arithmetization/plonk/detail/lookup_table_definition.hpp>
#include <nil/blueprint/components/algebra/fixedpoint/tables.hpp>

namespace nil {
    namespace blueprint {
        namespace components {

            ////////////////////////////////////////////////////////////////////
            //////// EXP A 16
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_exp_a16_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_exp_a16_table";
                static constexpr const char *SUBTABLE_NAME = "full";
                static constexpr const char *FULL_TABLE_NAME = "fixedpoint_exp_a16_table/full";

                // TACEO_TODO this hardcoded 0/1 is probably wrong
                fixedpoint_exp_a16_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SUBTABLE_NAME] = {{0, 1}, 0, fixedpoint_tables::ExpALen - 1};
                }

                virtual void generate() {
                    auto input = fixedpoint_tables::get_exp_a_input();
                    auto output = fixedpoint_tables::get_exp_a_16();
                    this->_table = {input, output};
                }

                virtual std::size_t get_columns_number() {
                    return 2;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::ExpALen;
                }
            };

            ////////////////////////////////////////////////////////////////////
            //////// EXP A 32
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_exp_a32_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_exp_a32_table";
                static constexpr const char *SUBTABLE_NAME = "full";
                static constexpr const char *FULL_TABLE_NAME = "fixedpoint_exp_a32_table/full";

                // TACEO_TODO this hardcoded 0/1 is probably wrong
                fixedpoint_exp_a32_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SUBTABLE_NAME] = {{0, 1}, 0, fixedpoint_tables::ExpALen - 1};
                }

                virtual void generate() {
                    auto input = fixedpoint_tables::get_exp_a_input();
                    auto output = fixedpoint_tables::get_exp_a_32();
                    this->_table = {input, output};
                }

                virtual std::size_t get_columns_number() {
                    return 2;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::ExpALen;
                }
            };

            ////////////////////////////////////////////////////////////////////
            //////// EXP B 16
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_exp_b16_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_exp_b16_table";
                static constexpr const char *SUBTABLE_NAME = "full";
                static constexpr const char *FULL_TABLE_NAME = "fixedpoint_exp_b16_table/full";

                // TACEO_TODO this hardcoded 0/1 is probably wrong
                fixedpoint_exp_b16_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SUBTABLE_NAME] = {{0, 1}, 0, fixedpoint_tables::ExpBLen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::ExpBLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto output = fixedpoint_tables::get_exp_b_16();
                    this->_table = {input, output};
                }

                virtual std::size_t get_columns_number() {
                    return 2;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::ExpBLen;
                }
            };

            ////////////////////////////////////////////////////////////////////
            //////// EXP B 32
            ////////////////////////////////////////////////////////////////////

            template<typename BlueprintFieldType>
            class fixedpoint_exp_b32_table
                : public nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType> {

                using lookup_table_definition =
                    typename nil::crypto3::zk::snark::detail::lookup_table_definition<BlueprintFieldType>;
                using fixedpoint_tables = FixedPointTables<BlueprintFieldType>;

            public:
                static constexpr const char *TABLE_NAME = "fixedpoint_exp_b32_table";
                static constexpr const char *SUBTABLE_NAME = "full";
                static constexpr const char *FULL_TABLE_NAME = "fixedpoint_exp_b32_table/full";

                // TACEO_TODO this hardcoded 0/1 is probably wrong
                fixedpoint_exp_b32_table() : lookup_table_definition(TABLE_NAME) {
                    this->subtables[SUBTABLE_NAME] = {{0, 1}, 0, fixedpoint_tables::ExpBLen - 1};
                }

                virtual void generate() {
                    BLUEPRINT_RELEASE_ASSERT(fixedpoint_tables::RangeLen == fixedpoint_tables::ExpBLen);
                    auto input = fixedpoint_tables::get_range_table();
                    auto output = fixedpoint_tables::get_exp_b_32();
                    this->_table = {input, output};
                }

                virtual std::size_t get_columns_number() {
                    return 2;
                }

                virtual std::size_t get_rows_number() {
                    return fixedpoint_tables::ExpBLen;
                }
            };

        }    // namespace components
    }        // namespace blueprint
}    // namespace nil

#endif    // CRYPTO3_BLUEPRINT_PLONK_FIXEDPOINT_EXP_TABLE_HPP
