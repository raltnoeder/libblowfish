/**
 * Block cipher implementing the Blowfish algorithm
 *
 * @version 2015-07-28
 * @author  Robert Altnoeder (r.altnoeder@gmx.net)
 *
 * Copyright (C) 2015 Robert ALTNOEDER
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided that
 * the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the distribution.
 *  3. The name of the author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <blowfish.h>
#include <string.h>

extern const bf_state BF_INIT_STATE;

extern const size_t BF_P_BOXES;
extern const size_t BF_S_BOXES;
extern const size_t BF_S_BOX_ENTRIES;

// Cipher rounds
const size_t BF_ROUNDS = 16;

// Step width for the unrolled loops
const size_t BF_UNROLLED_STEP =  2;

static inline uint32_t blowfish_f(bf_state *state, uint32_t value);


/**
 * Initializes a bf_state object
 *
 * @param state The bf_state object to initialize
 */
void blowfish_init(bf_state *state)
{
    memcpy(state, &BF_INIT_STATE, sizeof (bf_state));
}


/**
 * Clears the cipher's state
 *
 * @param state The bf_state object to clear
 */
void blowfish_clear(bf_state *state)
{
    // Clear the P Box
    for (size_t p_index = 0; p_index < BF_P_BOXES; ++p_index)
    {
        state->p_box[p_index] = 0;
    }

    // Clear the S boxes
    for (size_t s_box_index = 0; s_box_index < BF_S_BOXES; ++s_box_index)
    {
        for (size_t s_entry_index = 0; s_entry_index < BF_S_BOX_ENTRIES; ++s_entry_index)
        {
            state->s_box[s_box_index][s_entry_index] = 0;
        }
    }
}


/**
 * Sets the encryption key
 *
 * @param state      The cipher state object
 * @param key        The key to initialize the cipher with
 * @param key_length The length of the key
 */
void blowfish_set_key(bf_state *state, const unsigned char *key, size_t key_length)
{
    // Apply the key to the P box
    {
        size_t key_index = 0;
        for (size_t p_index = 0; p_index < BF_P_BOXES; ++p_index)
        {
            uint32_t value = 0;
            // Load 4 key bytes
            for (uint32_t counter = 0; counter < 4; ++counter)
            {
                value = value << 8;
                value |= key[key_index];
                ++key_index;
                key_index %= key_length;
            }
            state->p_box[p_index] ^= value;
        }
    }

    // Initialize the P box and S boxes
    {
        uint32_t data_l = 0;
        uint32_t data_r = 0;

        // Initialize the P box
        for (size_t p_index = 0; p_index < BF_P_BOXES; p_index += BF_UNROLLED_STEP)
        {
            blowfish_encrypt(state, &data_l, &data_r);
            state->p_box[p_index] = data_l;
            state->p_box[p_index + 1] = data_r;
        }

        // Initialize the S boxes
        for (size_t s_box_index = 0; s_box_index < BF_S_BOXES; ++s_box_index)
        {
            for (size_t s_entry_index = 0;
                 s_entry_index < BF_S_BOX_ENTRIES;
                 s_entry_index += BF_UNROLLED_STEP)
            {
                blowfish_encrypt(state, &data_l, &data_r);
                state->s_box[s_box_index][s_entry_index] = data_l;
                state->s_box[s_box_index][s_entry_index + 1] = data_r;
            }
        }
    }
}


/**
 * Returns the cipher text for a single block of plain text input
 *
 * @param state The cipher state object
 * @param data  The plain text to encrypt
 * @return      The cipher text for the supplied plain text
 */
uint64_t blowfish_encrypt64(bf_state *state, uint64_t data)
{
    uint32_t data_l = (uint32_t) (data >> 32);
    uint32_t data_r = (uint32_t) data;

    blowfish_encrypt(state, &data_l, &data_r);

    uint64_t encrypted = (((uint64_t) data_l) << 32) + ((uint64_t) data_r);

    return encrypted;
}

/**
 * Returns the plain text for a single block of cipher text input
 *
 * @param state The cipher state object
 * @param data  The cipher text to decrypt
 * @return      The plain text for the supplied cipher text
 */
uint64_t blowfish_decrypt64(bf_state *state, uint64_t data)
{
    uint32_t data_l = (uint32_t) (data >> 32);
    uint32_t data_r = (uint32_t) data;

    blowfish_decrypt(state, &data_l, &data_r);

    uint64_t decrypted = (((uint64_t) data_l) << 32) + ((uint64_t) data_r);

    return decrypted;
}


/**
 * Encrypts the two 32 bit parts of a single 64 bit block of data
 *
 * @param state      The cipher state object
 * @param data_l_ref The left (first, big-endian high-order) 32 bits of data
 * @param data_r_ref The right (second, big-endian low-order) 32 bits of data
 */
void blowfish_encrypt(bf_state *state, uint32_t *data_l_ref, uint32_t *data_r_ref)
{
    uint32_t data_l = (*data_l_ref);
    uint32_t data_r = (*data_r_ref);

    for (size_t p_box_index = 0; p_box_index < BF_ROUNDS; p_box_index += BF_UNROLLED_STEP)
    {
        data_l ^= state->p_box[p_box_index];
        data_r ^= blowfish_f(state, data_l);
        data_r ^= state->p_box[p_box_index + 1];
        data_l ^= blowfish_f(state, data_r);
    }
    data_l ^= state->p_box[16];
    data_r ^= state->p_box[17];

    (*data_l_ref) = data_r;
    (*data_r_ref) = data_l;
}


/**
 * Decrypts the two 32 bit parts of a single 64 bit block of data
 *
 * @param state      The cipher state object
 * @param data_l_ref The left (first, big-endian high-order) 32 bits of data
 * @param data_r_ref The right (second, big-endian low-order) 32 bits of data
 */
void blowfish_decrypt(bf_state *state, uint32_t *data_l_ref, uint32_t *data_r_ref)
{
    uint32_t data_l = (*data_l_ref);
    uint32_t data_r = (*data_r_ref);

    for (size_t p_box_index = BF_ROUNDS;
         p_box_index >= BF_UNROLLED_STEP;
         p_box_index -= BF_UNROLLED_STEP)
    {
        data_l ^= state->p_box[p_box_index + 1];
        data_r ^= blowfish_f(state, data_l);
        data_r ^= state->p_box[p_box_index];
        data_l ^= blowfish_f(state, data_r);
    }
    data_l ^= state->p_box[1];
    data_r ^= state->p_box[0];

    (*data_l_ref) = data_r;
    (*data_r_ref) = data_l;
}


/**
 * The Blowfish algorithm's "F" function
 *
 * @param state The cipher state object
 * @param value The input value to operate on
 * @return      The result of the Blowfish algorithm's "F" function
 */
static inline uint32_t blowfish_f(bf_state *state, uint32_t value)
{
    uint32_t result = state->s_box[0][value >> 24];
    result += state->s_box[1][(value >> 16) & 0xFF];
    result ^= state->s_box[2][(value >>  8) & 0xFF];
    result += state->s_box[3][value & 0xFF];

    return result;
}
