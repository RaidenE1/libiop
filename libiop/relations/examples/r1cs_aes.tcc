/** @file
 *****************************************************************************
 Implementation of AES R1CS example generator
 *****************************************************************************
 * @copyright  MIT license (see LICENSE file)
 ******************************************************************************/

#include <cassert>
#include <stdexcept>

#include "libiop/algebra/utils.hpp"
#include "libiop/relations/examples/r1cs_aes_constraints.hpp"
#include "libiop/relations/examples/r1cs_examples.hpp"

namespace libiop {

template<typename FieldT>
r1cs_example<FieldT> generate_aes_r1cs_example()
{
    r1cs_constraint_system<FieldT> cs;
    
    // 1. set basic parameters
    const unsigned int block_words = AES_BLOCK_WORDS;
    const unsigned int num_rounds = ROUNDS_128;
    
    // 2. set variable size
    cs.primary_input_size_ = 31;  // 16 bytes plaintext + 16 bytes key
    const size_t padded_aux_size = (1 << 13) - 1 - cs.primary_input_size_;  // 8191 - 31 = 8160
    cs.auxiliary_input_size_ = padded_aux_size;
    
    // ensure total variable count is 2^13-1 = 8191
    assert(cs.primary_input_size_ + cs.auxiliary_input_size_ == (1 << 13) - 1);
    // cs.auxiliary_input_size_ = (16 * num_rounds) + 176 + 1;  // state variable + round key

    // 3. variable allocation
    const size_t PLAINTEXT_OFFSET = 1;
    const size_t KEY_OFFSET = PLAINTEXT_OFFSET + 15;
    const size_t STATE_OFFSET = KEY_OFFSET + 16;
    const size_t ROUND_KEY_OFFSET = STATE_OFFSET + (16 * num_rounds);
    const size_t MOVED_INPUT_OFFSET = 0;
    
    add_moved_input_validation_constraints(cs, MOVED_INPUT_OFFSET);
    // 4. key expansion constraints
    add_key_expansion_constraints(cs, KEY_OFFSET, ROUND_KEY_OFFSET, 
                                block_words, num_rounds);

    // 5. encryption process constraints
    size_t current_state = STATE_OFFSET;
    
    // 5.1 initial round key addition
    add_round_key_constraints(cs, PLAINTEXT_OFFSET, ROUND_KEY_OFFSET, 
                            current_state, block_words);

    // 5.2 main round constraints
    for (size_t round = 1; round <= num_rounds; round++)
    {
        size_t next_state = current_state + 16;
        
        // SubBytes
        add_sub_bytes_constraints(cs, current_state, next_state, block_words);
        current_state = next_state;
        next_state += 16;
        
        // ShiftRows
        add_shift_rows_constraints(cs, current_state, block_words);
        
        // MixColumns
        if (round != num_rounds) {
            add_mix_columns_constraints(cs, current_state, block_words);
        }
        
        // AddRoundKey
        add_round_key_constraints(cs, current_state, 
                                ROUND_KEY_OFFSET + (round * 16), 
                                next_state, block_words);
        current_state = next_state;
    }

    // 6. generate random input
    r1cs_primary_input<FieldT> primary_input;
    r1cs_auxiliary_input<FieldT> auxiliary_input;

    // generate random primary input
    const size_t num_inputs = cs.primary_input_size_; // 31字节
    for (size_t i = 0; i < num_inputs; ++i) {
        primary_input.push_back(FieldT(rand() % 256));
    }

    auxiliary_input.push_back(FieldT(rand() % 256));
    // generate random auxiliary input
    for (size_t i = 1; i < cs.auxiliary_input_size_; ++i) {
        auxiliary_input.push_back(FieldT(rand() % 256));
    }

    return r1cs_example<FieldT>(std::move(cs), 
                               std::move(primary_input), 
                               std::move(auxiliary_input));
}

} // libiop
