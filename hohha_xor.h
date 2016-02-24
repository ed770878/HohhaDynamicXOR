#ifndef HOHHA_XOR_H
#define HOHHA_XOR_H

#include <stdint.h>

struct hx_state {
	uint32_t key_mask;	/* key length mask */
	uint32_t key_jumps;	/* number of "jumps" */
	uint32_t s1;		/* first "salt" or "seed" */
	uint32_t s2;		/* second "salt" or "seed" */
	uint32_t m;		/* "moving pointer" (mod key_len) */
	uint32_t v;		/* "v" of key and plain crc */
	uint32_t cs;		/* just the plain crc */
	uint32_t opt;		/* algorithm options */
	uint8_t key[];		/* key "body" secret data */
};

/**
 * Initialize the key data of the state.
 *
 * @hx - hohha xor state
 * @key - key data to copy, or NULL
 * @key_len - length of the key data
 * @key_jumps - number of hohha xor jumps
 */
void hx_init_key(struct hx_state *hx, uint8_t *key,
		uint32_t key_len, uint32_t key_jumps);

/**
 * Initialize the salt and moving pointer of the state.
 *
 * The key length must already be initialized for "m".
 *
 * @hx - hohha xor state
 * @s1 - first salt
 * @s2 - second salt
 */
void hx_init_salt(struct hx_state *hx,
		 uint32_t s1, uint32_t s2);

/**
 * Set options to affect running the algorithm.
 *
 * @hx - hohha xor state
 * @opt - zero for defaults, otherwise see enum hx_opts.
 */
void hx_init_opt(struct hx_state *hx, uint32_t opt);

/**
 * Completely initialize the state from scratch.
 *
 * @hx - hohha xor state
 * @key - key data to copy, or NULL
 * @key_len - length of the key data
 * @key_jumps - number of hohha xor jumps
 * @s1 - first salt
 * @s2 - second salt
 */
void hx_init(struct hx_state *hx, uint8_t *key,
	     uint32_t key_len, uint32_t key_jumps,
	     uint32_t s1, uint32_t s2,
	     uint32_t opt);

/**
 * Perform the first even jump.
 */
void hx_jump0(struct hx_state *hx);

/**
 * Perform the first odd jump.
 */
void hx_jump1(struct hx_state *hx);

/**
 * Perform the next even jump.
 */
void hx_jump2(struct hx_state *hx);

/**
 * Perform the next odd jump.
 */
void hx_jump3(struct hx_state *hx);

/**
 * Perform the sequence of jumps, general case.
 */
void hx_jump(struct hx_state *hx);

/**
 * Get the xor of the plain and ciphertext of the current step.
 */
uint8_t hx_step_xor(struct hx_state *hx);

/**
* Update the "cs" and "v" using plaintext of the current step.
*/
void hx_step_crc(struct hx_state *hx, uint8_t word);

/**
* Return the crc32 of the plaintext after encrypting or decrypting.
*/
uint32_t hx_text_crc(struct hx_state *hx);

/**
 * Encrypt a message using hohha xor.
 *
 * @xd - properly initialized hohha xor state.
 * @in_buf - plaintext to encrypt.
 * @out_buf - destination buffer for ciphertext.
 * @len - length of text to encrypt, in bytes.
 */
void hx_encrypt(struct hx_state *hx,
		uint8_t *in_buf,
		uint8_t *out_buf,
		uint32_t len);

/**
 * Decrypt a message using hohha xor.
 *
 * @xd - properly initialized hohha xor state.
 * @in_buf - ciphertext to decrypt.
 * @out_buf - destination buffer for plaintext.
 * @len - length of text to decrypt, in bytes.
 */
void hx_decrypt(struct hx_state *hx,
		uint8_t *in_buf,
		uint8_t *out_buf,
		uint32_t len);

#endif
