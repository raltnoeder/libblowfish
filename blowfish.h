#ifndef BLOWFISH_H
#define	BLOWFISH_H

#include <blowfish_types.h>

/**
 * Initializes a bf_state object
 *
 * @param state The bf_state object to initialize
 */
void blowfish_init(bf_state *state);

/**
 * Clears the cipher's state
 *
 * @param state The bf_state object to clear
 */
void blowfish_clear(bf_state *state);

/**
 * Sets the encryption key
 *
 * @param state      The cipher state object
 * @param key        The key to initialize the cipher with
 * @param key_length The length of the key
 */
void blowfish_set_key(bf_state *state, const unsigned char *key, size_t key_length);

/**
 * Returns the cipher text for a single block of plain text input
 *
 * @param state The cipher state object
 * @param data  The plain text to encrypt
 * @return      The cipher text for the supplied plain text
 */
uint64_t blowfish_encrypt64(bf_state *state, uint64_t data);

/**
 * Returns the plain text for a single block of cipher text input
 *
 * @param state The cipher state object
 * @param data  The cipher text to decrypt
 * @return      The plain text for the supplied cipher text
 */
uint64_t blowfish_decrypt64(bf_state *state, uint64_t data);

/**
 * Encrypts the two 32 bit parts of a single 64 bit block of data
 *
 * @param state      The cipher state object
 * @param data_l_ref The left (first, big-endian high-order) 32 bits of data
 * @param data_r_ref The right (second, big-endian low-order) 32 bits of data
 */
void blowfish_encrypt(bf_state *state, uint32_t *data_l_ref, uint32_t *data_r_ref);

/**
 * Decrypts the two 32 bit parts of a single 64 bit block of data
 *
 * @param state      The cipher state object
 * @param data_l_ref The left (first, big-endian high-order) 32 bits of data
 * @param data_r_ref The right (second, big-endian low-order) 32 bits of data
 */
void blowfish_decrypt(bf_state *state, uint32_t *data_l_ref, uint32_t *data_r_ref);

#endif	/* BLOWFISH_H */
