/**
 * Blowfish CFB mode functions
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

#include <blowfish_cfb64.h>

// Block size in bytes (8 == 64 bits)
const size_t BF_CFB64_BLOCK_SIZE = 8;

// Maximum shift width for the remaining data in bytes (7 == 56 bits)
const size_t BF_CFB64_REMAINDER_BASE = 7;

// Byte mask, used to extract a single byte from a bigger datatype
const uint64_t BF_CFB64_BYTE_MASK = 0xFF;

// Byte shift value (8 bits == 1 byte)
const size_t BF_CFB64_BYTE_SHIFT = 8;


/**
 * Encrypts the supplied data in-place
 *
 * @param cfb_state   CFB mode state object
 * @param data        Plain text input data to encrypt
 * @param data_length Length of the input data
 */
void blowfish_cfb64_encrypt(bf_cfb64_state *cfb_state,
                            unsigned char *data, size_t data_length)
{
    uint64_t cipher_text = cfb_state->feedback;
    size_t full_blocks = data_length / BF_CFB64_BLOCK_SIZE;
    for (size_t block_index = 0; block_index < full_blocks; ++block_index)
    {
        cipher_text = blowfish_encrypt64(cfb_state->cipher_state, cipher_text);

        uint64_t plain_text = 0;
        // Get the plain text from the data string
        for (size_t offset = 0; offset < BF_CFB64_BLOCK_SIZE; ++offset)
        {
            size_t data_index = block_index * BF_CFB64_BLOCK_SIZE + offset;
            plain_text = plain_text << BF_CFB64_BYTE_SHIFT;
            plain_text |= data[data_index];
        }

        // XOR cipher text and plain text
        cipher_text ^= plain_text;

        // Write the cipher text back to the data string
        for (size_t offset = 0; offset < BF_CFB64_BLOCK_SIZE; ++offset)
        {
            size_t data_index = block_index * BF_CFB64_BLOCK_SIZE + offset;
            data[data_index] = (unsigned char) (cipher_text >> ((BF_CFB64_REMAINDER_BASE -
                               offset) * BF_CFB64_BYTE_SHIFT) & BF_CFB64_BYTE_MASK);
        }
    }

    size_t remainder = data_length % BF_CFB64_BLOCK_SIZE;
    if (remainder > 0)
    {
        cipher_text = blowfish_encrypt64(cfb_state->cipher_state, cipher_text);

        uint64_t plain_text = 0;
        // Get the remainder of the plain text from the data string
        for (size_t offset = 0; offset < remainder; ++offset)
        {
            size_t data_index = data_length - remainder + offset;
            plain_text = plain_text << BF_CFB64_BYTE_SHIFT;
            plain_text |= data[data_index];
        }
        // Finish the shift to the left
        plain_text = plain_text << ((BF_CFB64_BLOCK_SIZE - remainder) * BF_CFB64_BYTE_SHIFT);

        cipher_text ^= plain_text;

        // Write the remainder of the cipher text back to the data string
        for (size_t offset = 0; offset < remainder; ++offset)
        {
            size_t data_index = data_length - remainder + offset;
            data[data_index] = (unsigned char) (cipher_text >> ((BF_CFB64_REMAINDER_BASE -
                               offset) * BF_CFB64_BYTE_SHIFT) & BF_CFB64_BYTE_MASK);
        }
    }

    cfb_state->feedback = cipher_text;
}


/**
 * Decrypts the supplied data in-place
 *
 * @param cfb_state   CFB mode state object
 * @param data        Cipher text input data to decrypt
 * @param data_length Length of the input data
 */
void blowfish_cfb64_decrypt(bf_cfb64_state *cfb_state,
                            unsigned char *data, size_t data_length)
{
    uint64_t cipher_base = cfb_state->feedback;

    size_t full_blocks = data_length / BF_CFB64_BLOCK_SIZE;
    for (size_t block_index = 0; block_index < full_blocks; ++block_index)
    {
        // Encrypt the current block
        cipher_base = blowfish_encrypt64(cfb_state->cipher_state, cipher_base);

        // Get the cipher text from the data string
        uint64_t cipher_text = 0;
        for (size_t offset = 0; offset < BF_CFB64_BLOCK_SIZE; ++offset)
        {
            size_t data_index = block_index * BF_CFB64_BLOCK_SIZE + offset;
            cipher_text = cipher_text << BF_CFB64_BYTE_SHIFT;
            cipher_text |= data[data_index];
        }

        // Decrypt the block
        uint64_t plain_text = cipher_text ^ cipher_base;

        // Write the plain text back to the data string
        for (size_t offset = 0; offset < BF_CFB64_BLOCK_SIZE; ++offset)
        {
            size_t data_index = block_index * BF_CFB64_BLOCK_SIZE + offset;
            data[data_index] = (unsigned char) (plain_text >> ((BF_CFB64_REMAINDER_BASE -
                               offset) * BF_CFB64_BYTE_SHIFT) & BF_CFB64_BYTE_MASK);
        }

        // Set the cipher input for the next block
        cipher_base = cipher_text;
    }

    size_t remainder = data_length % BF_CFB64_BLOCK_SIZE;
    if (remainder > 0)
    {
        cipher_base = blowfish_encrypt64(cfb_state->cipher_state, cipher_base);

        uint64_t cipher_text = 0;
        for (size_t offset = 0; offset < remainder; ++offset)
        {
            size_t data_index = data_length - remainder + offset;
            cipher_text = cipher_text << BF_CFB64_BYTE_SHIFT;
            cipher_text |= data[data_index];
        }
        // Finish the shift to the left
        cipher_text = cipher_text << ((BF_CFB64_BLOCK_SIZE - remainder) * BF_CFB64_BYTE_SHIFT);

        // Decrypt the block
        uint64_t plain_text = cipher_text ^ cipher_base;

        // Write the remainder of the plain text back to the data string
        for (size_t offset = 0; offset < remainder; ++offset)
        {
            size_t data_index = data_length - remainder + offset;
            data[data_index] = (unsigned char) (plain_text >> ((BF_CFB64_REMAINDER_BASE -
                               offset) * BF_CFB64_BYTE_SHIFT) & BF_CFB64_BYTE_MASK);
        }
    }

    cfb_state->feedback = cipher_base;
}


/**
 * Initializes a bf_cfb64_state object
 *
 * @param cfb_state   The object to initialize
 * @param state       Cipher state object
 * @param init_vector The initialization vector for the cipher
 */
void blowfish_cfb64_init(bf_cfb64_state *cfb_state, bf_state *state,
                         uint64_t init_vector)
{
    cfb_state->cipher_state = state;
    cfb_state->feedback     = init_vector;
}


/**
 * Sets the initialization vector
 *
 * @param cfb_state   The object to initialize
 * @param init_vector The initialization vector for the cipher
 */
void blowfish_cfb64_set_init_vector(bf_cfb64_state *cfb_state, uint64_t init_vector)
{
    cfb_state->feedback = init_vector;
}


/**
 * Creates a new bf_cfb64_state object including the contained bf_state object
 */
bf_cfb64_state *blowfish_cfb64_alloc(void)
{
    bf_cfb64_state *cfb_state = NULL;

    bf_state *cipher_state = malloc(sizeof (bf_state));
    if (cipher_state != NULL)
    {
        cfb_state = malloc(sizeof (bf_cfb64_state));
        if (cfb_state != NULL)
        {
            cfb_state->cipher_state = cipher_state;
            cfb_state->feedback     = 0;
            blowfish_init(cipher_state);
        }
        else
        {
            free(cipher_state);
        }
    }

    return cfb_state;
}


/**
 * Releases a bf_cfb64_state object including the contained bf_state object
 */
void blowfish_cfb64_dealloc(bf_cfb64_state *cfb_state)
{
    free(cfb_state->cipher_state);
    free(cfb_state);
}


/**
 * Allocates and initializes a new bf_cfb64_state object
 */
bf_cfb64_state *blowfish_cfb64_create(const unsigned char *key, size_t key_length,
                                      uint64_t init_vector)
{
    bf_cfb64_state *cfb_state = blowfish_cfb64_alloc();
    if (cfb_state != NULL)
    {
        blowfish_set_key(cfb_state->cipher_state, key, key_length);
        cfb_state->feedback = init_vector;
    }

    return cfb_state;
}


/**
 * Clears and deallocates a bf_cfb64_state object
 */
void blowfish_cfb64_destroy(bf_cfb64_state *cfb_state)
{
    cfb_state->feedback = 0;
    blowfish_clear(cfb_state->cipher_state);
    blowfish_cfb64_dealloc(cfb_state);
}
