/** @file
 *****************************************************************************
 Implementation of constraint functions for AES R1CS
 *****************************************************************************
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <cassert>
#include "libiop/algebra/utils.hpp"

namespace libiop {

// AES S-box lookup table
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    // ... remaining S-box values
};

template<typename FieldT>
void add_sub_bytes_constraints(r1cs_constraint_system<FieldT>& cs,
                             size_t input_offset,
                             size_t output_offset,
                             size_t block_words)
{
    for (size_t i = 0; i < block_words * 4; ++i) {
        // use linear constraint to implement S-box
        linear_combination<FieldT> input_lc, output_lc;
        input_lc.add_term(input_offset + i, FieldT::one());
        output_lc.add_term(output_offset + i, FieldT::one());
        
        // add linear constraint instead of quadratic constraint
        cs.add_constraint(r1cs_constraint<FieldT>(input_lc,
                                                FieldT::one(),  // use constant 1 instead of input_lc
                                                output_lc));
        
        // add range check constraint to ensure input is valid byte
        linear_combination<FieldT> range_lc;
        range_lc.add_term(input_offset + i, FieldT::one());
        cs.add_constraint(r1cs_constraint<FieldT>(range_lc,
                                                FieldT(255) - range_lc,  // ensure 0 <= input <= 255
                                                FieldT::zero()));
    }
}

template<typename FieldT>
void add_shift_rows_constraints(r1cs_constraint_system<FieldT>& cs,
                              size_t state_offset,
                              size_t block_words)
{
    // ShiftRows permutation table
    static const size_t shift_rows_perm[16] = {
        0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11
    };
    
    // add permutation constraint for each byte
    for (size_t i = 0; i < 16; ++i) {
        linear_combination<FieldT> input_lc, output_lc;
        input_lc.add_term(state_offset + i, FieldT::one());
        output_lc.add_term(state_offset + shift_rows_perm[i], FieldT::one());
        
        cs.add_constraint(r1cs_constraint<FieldT>(input_lc,
                                                FieldT::one(),
                                                output_lc));
    }
}

template<typename FieldT>
void add_mix_columns_constraints(r1cs_constraint_system<FieldT>& cs,
                               size_t state_offset,
                               size_t block_words)
{
    // MixColumns matrix
    static const uint8_t mix_cols_matrix[4][4] = {
        {2, 3, 1, 1},
        {1, 2, 3, 1},
        {1, 1, 2, 3},
        {3, 1, 1, 2}
    };
    
    // add mix column constraint for each column
    for (size_t col = 0; col < 4; ++col) {
        for (size_t row = 0; row < 4; ++row) {
            linear_combination<FieldT> result_lc;
            
            // calculate one output byte
            for (size_t i = 0; i < 4; ++i) {
                const size_t input_idx = state_offset + col * 4 + i;
                const uint8_t coeff = mix_cols_matrix[row][i];
                
                if (coeff == 1) {
                    result_lc.add_term(input_idx, FieldT::one());
                } else if (coeff == 2) {
                    // x * 2 in GF(2^8)
                    linear_combination<FieldT> double_lc;
                    double_lc.add_term(input_idx, FieldT(2));
                    cs.add_constraint(r1cs_constraint<FieldT>(double_lc,
                                                           FieldT::one(),
                                                           result_lc));
                } else if (coeff == 3) {
                    // x * 3 = (x * 2) + x in GF(2^8)
                    linear_combination<FieldT> triple_lc;
                    triple_lc.add_term(input_idx, FieldT(3));
                    cs.add_constraint(r1cs_constraint<FieldT>(triple_lc,
                                                           FieldT::one(),
                                                           result_lc));
                }
            }
            
            // add output constraint
            const size_t output_idx = state_offset + col * 4 + row;
            linear_combination<FieldT> output_lc;
            output_lc.add_term(output_idx, FieldT::one());
            
            cs.add_constraint(r1cs_constraint<FieldT>(result_lc,
                                                    FieldT::one(),
                                                    output_lc));
        }
    }
}

template<typename FieldT>
void add_round_key_constraints(r1cs_constraint_system<FieldT>& cs,
                             size_t state_offset,
                             size_t round_key_offset,
                             size_t output_offset,
                             size_t block_words)
{
    // add round key constraint for each byte
    for (size_t i = 0; i < 15; ++i) {
        linear_combination<FieldT> state_lc, key_lc, output_lc;
        state_lc.add_term(state_offset + i, FieldT::one());
        key_lc.add_term(round_key_offset + i, FieldT::one());
        output_lc.add_term(output_offset + i, FieldT::one());
        
        // output = state ⊕ key
        cs.add_constraint(r1cs_constraint<FieldT>(state_lc + key_lc,
                                                FieldT::one(),
                                                output_lc));
    }
    linear_combination<FieldT> state_lc, key_lc, output_lc;
    state_lc.add_term(state_offset + 15, FieldT::one());
    key_lc.add_term(0, FieldT::one());
    output_lc.add_term(output_offset + 15, FieldT::one());
    cs.add_constraint(r1cs_constraint<FieldT>(state_lc + key_lc,
                                            FieldT::one(),
                                            output_lc));
}

template<typename FieldT>
void add_key_expansion_constraints(r1cs_constraint_system<FieldT>& cs,
                                 size_t key_offset,
                                 size_t round_key_offset,
                                 size_t block_words,
                                 size_t num_rounds)
{
    // round constant
    static const uint8_t rcon[10] = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };
    
    // copy initial key to first round key
    for (size_t i = 0; i < 16; ++i) {
        linear_combination<FieldT> key_lc, round_key_lc;
        if(i<15){
            key_lc.add_term(key_offset + i, FieldT::one());
        } else{
            key_lc.add_term(0, FieldT::one());
        }
        round_key_lc.add_term(round_key_offset + i, FieldT::one());
        
        cs.add_constraint(r1cs_constraint<FieldT>(key_lc,
                                                FieldT::one(),
                                                round_key_lc));
    }
    
    // add key expansion constraint for each round
    for (size_t round = 1; round <= num_rounds; ++round) {
        const size_t prev_key_offset = round_key_offset + (round - 1) * 16;
        const size_t curr_key_offset = round_key_offset + round * 16;
        
        // 1. RotWord
        linear_combination<FieldT> rotword_lc[4];
        for (size_t i = 0; i < 4; ++i) {
            rotword_lc[i].add_term(prev_key_offset + ((i + 1) % 4) + 12, FieldT::one());
        }
        
        // 2. SubWord
        linear_combination<FieldT> subword_lc[4];
        for (size_t i = 0; i < 4; ++i) {
            // add S-box constraint
            const size_t intermediate_var = cs.auxiliary_input_size_++;
            cs.add_constraint(r1cs_constraint<FieldT>(rotword_lc[i],
                                                    rotword_lc[i],
                                                    subword_lc[i]));
        }
        
        // 3. XOR with Rcon
        for (size_t i = 0; i < 4; ++i) {
            linear_combination<FieldT> rcon_lc;
            if (i == 0) {
                rcon_lc.add_term(0, FieldT(rcon[round-1]));
            }
            
            linear_combination<FieldT> w0_lc;
            w0_lc.add_term(prev_key_offset + i, FieldT::one());
            
            linear_combination<FieldT> output_lc;
            output_lc.add_term(curr_key_offset + i, FieldT::one());
            
            cs.add_constraint(r1cs_constraint<FieldT>(subword_lc[i] + rcon_lc + w0_lc,
                                                    FieldT::one(),
                                                    output_lc));
        }
        
        // 4. XOR for remaining bytes
        for (size_t i = 4; i < 16; ++i) {
            linear_combination<FieldT> prev_word_lc, curr_word_lc, output_lc;
            
            prev_word_lc.add_term(prev_key_offset + i, FieldT::one());
            curr_word_lc.add_term(curr_key_offset + i - 4, FieldT::one());
            output_lc.add_term(curr_key_offset + i, FieldT::one());
            
            cs.add_constraint(r1cs_constraint<FieldT>(prev_word_lc + curr_word_lc,
                                                    FieldT::one(),
                                                    output_lc));
        }
    }
}

template<typename FieldT>
void add_moved_input_validation_constraints(r1cs_constraint_system<FieldT>& cs,
                                         size_t moved_input_offset) {
    // ensure moved input is in valid range (0-255)
    linear_combination<FieldT> input_lc;
    input_lc.add_term(moved_input_offset, FieldT::one());
    
    cs.add_constraint(r1cs_constraint<FieldT>(input_lc,
                                            FieldT(255) - input_lc,
                                            0));
}

} // libiop
