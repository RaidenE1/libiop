/** @file
 *****************************************************************************
 Declaration of constraint functions for AES R1CS
 *****************************************************************************
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef RELATIONS__EXAMPLES__R1CS_AES_CONSTRAINTS_HPP_
#define RELATIONS__EXAMPLES__R1CS_AES_CONSTRAINTS_HPP_

#include "libiop/relations/r1cs.hpp"

// AES constants
#define AES_BLOCK_WORDS 4  // AES block size in words (128 bits = 4 words)
#define ROUNDS_128 10      // Number of rounds for AES-128

namespace libiop {

template<typename FieldT>
void add_sub_bytes_constraints(r1cs_constraint_system<FieldT>& cs,
                             size_t input_offset,
                             size_t output_offset,
                             size_t block_words);

template<typename FieldT>
void add_shift_rows_constraints(r1cs_constraint_system<FieldT>& cs,
                              size_t state_offset,
                              size_t block_words);

template<typename FieldT>
void add_mix_columns_constraints(r1cs_constraint_system<FieldT>& cs,
                               size_t state_offset,
                               size_t block_words);

template<typename FieldT>
void add_round_key_constraints(r1cs_constraint_system<FieldT>& cs,
                             size_t state_offset,
                             size_t round_key_offset,
                             size_t output_offset,
                             size_t block_words);

template<typename FieldT>
void add_key_expansion_constraints(r1cs_constraint_system<FieldT>& cs,
                                 size_t key_offset,
                                 size_t round_key_offset,
                                 size_t block_words,
                                 size_t num_rounds);

template<typename FieldT>
void add_moved_input_validation_constraints(r1cs_constraint_system<FieldT>& cs,
                                         size_t moved_input_offset);
} // libiop
#include "libiop/relations/examples/r1cs_aes_constraints.tcc"

#endif // RELATIONS__EXAMPLES__R1CS_AES_CONSTRAINTS_HPP_
