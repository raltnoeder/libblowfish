#include <blowfish.h>

#ifndef BLOWFISH_CFB64_H
#define	BLOWFISH_CFB64_H

typedef struct bf_cfb64_state_s bf_cfb64_state;
struct bf_cfb64_state_s
{
    bf_state *cipher_state;
    uint64_t feedback;
};

/**
 * Encrypts the supplied data in-place
 *
 * @param cfb_state   CFB mode state object
 * @param data        Plain text input data to encrypt
 * @param data_length Length of the input data
 */
void blowfish_cfb64_encrypt(bf_cfb64_state *cfb_state,
                            unsigned char *data, size_t data_length);

/**
 * Decrypts the supplied data in-place
 *
 * @param cfb_state   CFB mode state object
 * @param data        Cipher text input data to decrypt
 * @param data_length Length of the input data
 */
void blowfish_cfb64_decrypt(bf_cfb64_state *cfb_state,
                            unsigned char *data, size_t data_length);

/**
 * Initializes a bf_cfb64_state object
 *
 * @param cfb_state   The object to initialize
 * @param state       Cipher state object
 * @param init_vector The initialization vector for the cipher
 */
void blowfish_cfb64_init(bf_cfb64_state *cfb_state, bf_state *state,
                         uint64_t init_vector);

/**
 * Sets the initialization vector
 *
 * @param cfb_state   The object to initialize
 * @param init_vector The initialization vector for the cipher
 */
void blowfish_cfb64_set_init_vector(bf_cfb64_state *cfb_state, uint64_t init_vector);

/**
 * Creates a new bf_cfb64_state object including the contained bf_state object
 */
bf_cfb64_state *blowfish_cfb64_alloc(void);

/**
 * Releases a bf_cfb64_state object including the contained bf_state object
 */
void blowfish_cfb64_dealloc(bf_cfb64_state *cfb_state);

/**
 * Allocates and initializes a new bf_cfb64_state object
 */
bf_cfb64_state *blowfish_cfb64_create(const unsigned char *key, size_t key_length,
                                      uint64_t init_vector);

/**
 * Clears and deallocates a bf_cfb64_state object
 */
void blowfish_cfb64_destroy(bf_cfb64_state *cfb_state);


#endif	/* BLOWFISH_CFB64_H */
