//---------------------------------------------------------------------------//
// Copyright (c) 2020-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
#define CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP

#include <algorithm>
#include <limits>

#include <nil/crypto3/zk/snark/arithmetization/plonk/table_description.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/constraint_system.hpp>
#include <nil/crypto3/zk/snark/arithmetization/plonk/assignment.hpp>

#include <nil/blueprint/component.hpp>
#include <nil/blueprint/assert.hpp>
#include <nil/blueprint/gate_id.hpp>
#include <nil/blueprint/blueprint/plonk/circuit.hpp>

namespace nil {
    namespace blueprint {

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class assignment;

        template<typename ArithmetizationType, std::size_t... BlueprintParams>
        class circuit;

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        class assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>>
                : public crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType,
                        ArithmetizationParams> {

            using zk_type = crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType,
                    ArithmetizationParams>;

            typedef crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                    ArithmetizationParams> ArithmetizationType;

            using var = crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>;
            using value_type = typename BlueprintFieldType::value_type;

            std::size_t next_selector_index = 0;
            std::uint32_t _allocated_rows = 0;
            std::vector<value_type> _private_storage;
        public:
            static constexpr const std::size_t PRIVATE_STORAGE_INDEX = std::numeric_limits<std::size_t>::max();

            assignment() :
                    crypto3::zk::snark::plonk_assignment_table<BlueprintFieldType,
                            ArithmetizationParams>() {
            }

            value_type &selector(std::size_t selector_index, std::uint32_t row_index) {

                assert(selector_index < this->_public_table._selectors.size());

                if (this->_public_table._selectors[selector_index].size() <= row_index)
                    this->_public_table._selectors[selector_index].resize(row_index + 1);

                return this->_public_table._selectors[selector_index][row_index];
            }

            value_type selector(std::size_t selector_index, std::uint32_t row_index) const {

                assert(selector_index < this->_public_table._selectors.size());
                assert(row_index < this->_public_table._selectors[selector_index].size());

                return this->_public_table._selectors[selector_index][row_index];
            }

            std::uint32_t allocated_rows() const {
                return _allocated_rows;
            }

            void enable_selector(const std::size_t selector_index, const std::size_t row_index) {

                selector(selector_index, row_index) = BlueprintFieldType::value_type::one();
            }

            void enable_selector(const std::size_t selector_index,
                                 const std::size_t begin_row_index,
                                 const std::size_t end_row_index,
                                 const std::size_t index_step = 1) {

                for (std::size_t row_index = begin_row_index; row_index <= end_row_index; row_index += index_step) {

                    enable_selector(selector_index, row_index);
                }
            }

            value_type &witness(std::uint32_t witness_index, std::uint32_t row_index) {
                BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);

                if (this->_private_table._witnesses[witness_index].size() <= row_index)
                    this->_private_table._witnesses[witness_index].resize(row_index + 1);

                _allocated_rows = std::max(_allocated_rows, row_index + 1);
                return this->_private_table._witnesses[witness_index][row_index];
            }

            value_type witness(std::uint32_t witness_index, std::uint32_t row_index) const {
                BLUEPRINT_ASSERT(witness_index < ArithmetizationParams::WitnessColumns);
                BLUEPRINT_ASSERT(row_index < this->_private_table._witnesses[witness_index].size());

                return this->_private_table._witnesses[witness_index][row_index];
            }

            value_type &public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) {

                BLUEPRINT_ASSERT(public_input_index < zk_type::public_inputs_amount());

                if (zk_type::public_input_column_size(public_input_index) <= row_index)
                    this->_public_table._public_inputs[public_input_index].resize(row_index + 1);

                return this->_public_table._public_inputs[public_input_index][row_index];
            }

            value_type public_input(
                std::uint32_t public_input_index, std::uint32_t row_index) const {

                BLUEPRINT_ASSERT(public_input_index < zk_type::public_inputs_amount());
                BLUEPRINT_ASSERT(row_index < zk_type::public_input_column_size(public_input_index));

                return zk_type::public_input(public_input_index)[row_index];
            }

            value_type &constant(
                std::uint32_t constant_index, std::uint32_t row_index) {

                assert(constant_index < zk_type::constants_amount());

                if (zk_type::constant_column_size(constant_index) <= row_index)
                    this->_public_table._constants[constant_index].resize(row_index + 1);

                _allocated_rows = std::max(_allocated_rows, row_index + 1);
                return this->_public_table._constants[constant_index][row_index];
            }

            value_type constant(
                std::uint32_t constant_index, std::uint32_t row_index) const {

                BLUEPRINT_ASSERT(constant_index < zk_type::constants_amount());
                BLUEPRINT_ASSERT(row_index < zk_type::constant_column_size(constant_index));

                return zk_type::constant(constant_index)[row_index];
            }

            value_type private_storage(std::uint32_t storage_index) const {
                BLUEPRINT_ASSERT(storage_index < _private_storage.size());
                return _private_storage[storage_index];
            }

            value_type &private_storage(std::uint32_t storage_index) {
                if (_private_storage.size() <= storage_index) {
                    _private_storage.resize(storage_index + 1);
                }
                return _private_storage[storage_index];
            }

            // Not required to be called; get_private_storage will automatically resize
            // But you might want to use this to clear
            void resize_private_storage(std::uint32_t new_size) {
                _private_storage.resize(new_size);
            }

            void clear_private_storage() {
                _private_storage.clear();
            }

            std::size_t private_storage_size() const {
                return _private_storage.size();
            }

            void export_table(std::ostream& os, bool wide_export = false) const {
                // wide_export is for e.g. potentiall fuzzer: does fixed width elements
                std::ios_base::fmtflags os_flags(os.flags());
                std::size_t witnesses_size = this->_private_table.witnesses_amount(),
                            public_size = this->_public_table.public_inputs_amount(),
                            constants_size = this->_public_table.constants_amount(),
                            selectors_size = this->_public_table.selectors_amount();
                std::uint32_t max_size = 0,
                              max_witnesses_size = 0,
                              max_public_inputs_size = 0,
                              max_constants_size = 0,
                              max_selectors_size = 0;
                for (std::uint32_t i = 0; i < witnesses_size; i++) {
                    max_witnesses_size = std::max(max_witnesses_size, this->_private_table.witness_column_size(i));
                }
                for (std::uint32_t i = 0; i < public_size; i++) {
                    max_public_inputs_size = std::max(max_public_inputs_size,
                                                      this->_public_table.public_input_column_size(i));
                }
                for (std::uint32_t i = 0; i < constants_size; i++) {
                    max_constants_size = std::max(max_constants_size, this->_public_table.constant_column_size(i));
                }
                for (std::uint32_t i = 0; i < selectors_size; i++) {
                    max_selectors_size = std::max(max_selectors_size, this->_public_table.selector_column_size(i));
                }
                os << std::dec;
                max_size = std::max({max_witnesses_size,
                                    max_public_inputs_size,
                                    max_constants_size,
                                    max_selectors_size});
                os << "witnesses_size: " << witnesses_size << " "
                   << "public_inputs_size: " << public_size << " "
                   << "constants_size: " << constants_size << " "
                   << "selectors_size: " << selectors_size << " "
                   << "max_size: " << max_size << "\n";

                os << std::hex << std::setfill('0');
                std::uint32_t width = wide_export ? (BlueprintFieldType::modulus_bits + 4 - 1) / 4 : 0;
                for (std::uint32_t i = 0; i < max_size; i++) {
                    for (std::uint32_t j = 0; j < witnesses_size; j++) {
                        os << std::setw(width)
                            << (i < this->_private_table.witness_column_size(j) ?
                                    this->_private_table.witness(j)[i] : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < public_size; j++) {
                        os << std::setw(width)
                            << (i < this->_public_table.public_input_column_size(j) ?
                                    this->_public_table.public_input(j)[i] : 0).data << " ";
                    }
                    os << "| ";
                    for (std::uint32_t j = 0; j < constants_size; j++) {
                        os << std::setw(width)
                            << (i < this->_public_table.constant_column_size(j) ?
                                    this->_public_table.constant(j)[i] : 0).data << " ";
                    }
                    os << "| ";
                    // Selectors only need a single bit, so we do not renew the size here
                    for (std::uint32_t j = 0; j < selectors_size - 1; j++) {
                        os << (i < this->_public_table.selector_column_size(j) ?
                                    this->_public_table.selector(j)[i] : 0).data << " ";
                    }
                    os << (i < this->_public_table.selector_column_size(selectors_size - 1) ?
                                this->_public_table.selector(selectors_size - 1)[i] : 0).data;
                    os << "\n";
                }
                os.flush();
                os.flags(os_flags);
            }
        };

        template<typename BlueprintFieldType,
                typename ArithmetizationParams>
        typename BlueprintFieldType::value_type var_value(
                const assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>> &input_assignment,
                const crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type> &input_var) {
            using var_column_type =
                typename crypto3::zk::snark::plonk_variable<typename BlueprintFieldType::value_type>::column_type;
            using assignment_type =
                assignment<crypto3::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>>;
            // This SHOULD be handled by a separate variable type
            // But adding a new variable type breaks assigner
            // So we add a type without actually adding a type
            if (input_var.index == assignment_type::PRIVATE_STORAGE_INDEX) {
                return input_assignment.private_storage(input_var.rotation);
            }
            switch(input_var.type){
                case var_column_type::witness:
                    return input_assignment.witness(input_var.index, input_var.rotation);
                case var_column_type::public_input:
                    return input_assignment.public_input(input_var.index, input_var.rotation);
                default:
                    return input_assignment.constant(input_var.index, input_var.rotation);
            }
        }

    }    // namespace blueprint
}    // namespace nil
#endif    // CRYPTO3_BLUEPRINT_ASSIGNMENT_PLONK_HPP
