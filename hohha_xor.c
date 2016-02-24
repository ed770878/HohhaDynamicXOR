#include <string.h>
#include <stdlib.h>

#include "hohha_xor.h"
#include "hohha_util.h"

static void (*hx_jump_fn(int key_jumps))(struct hx_state *hx);

void hx_init_key(struct hx_state *hx, uint8_t *key,
		 uint32_t key_len, uint32_t key_jumps)
{
	if (key)
		memcpy(hx->key, key, key_len);

	hx->jump_fn = hx_jump_fn(key_jumps);

	hx->key_mask = key_len - 1;
	hx->key_jumps = key_jumps;

	hx->v = crc32_data(key, key_len);
	hx->cs = ~0;

	dbg("key_mask %#xu key_jumps %u\n",
	    hx->key_mask, hx->key_jumps);
	dbg("cs %#x v %#x\n",
	    hx->cs, hx->v);
}

void hx_init_salt(struct hx_state *hx,
		  uint32_t s1, uint32_t s2)
{
	hx->s1 = s1;
	hx->s2 = s2;
	hx->m = (s1 >> 24) * (s2 >> 24);
	hx->m &= hx->key_mask;

	dbg("s1 %#x s2 %#x m %u\n",
	    hx->s1, hx->s2, hx->m);
}

void hx_init_opt(struct hx_state *hx, uint32_t opt)
{
	hx->opt = opt;
}

void hx_init(struct hx_state *hx, uint8_t *key,
	     uint32_t key_len, uint32_t key_jumps,
	     uint32_t s1, uint32_t s2,
	     uint32_t opt)
{
	hx_init_key(hx, key, key_len, key_jumps);
	hx_init_salt(hx, s1, s2);
	hx_init_opt(hx, opt);
}

void hx_vdbg(struct hx_state *hx, char *when)
{
	vdbg("%s s1 %#010x s2 %#010x m %u",
	     when, hx->s1, hx->s2, hx->m);
}

void hx_jump0(struct hx_state *hx)
{
	hx->s1 ^= hx->key[hx->m];
	hx->key[hx->m] = u8(hx->s2);
	hx->m ^= hx->s2; /* Note: s2 not v (see jump2) */
	hx->m &= hx->key_mask;
	hx->s2 = rol32(hx->s2, 1);

	hx_vdbg(hx, "jump0");
}

void hx_jump1(struct hx_state *hx)
{
	hx->s2 ^= hx->key[hx->m];
	hx->key[hx->m] = u8(hx->s1);
	hx->m ^= hx->v; /* Note: v not s1 (see jump3) */
	hx->m &= hx->key_mask;
	hx->s1 = ror32(hx->s1, 1);

	hx_vdbg(hx, "jump1");
}

void hx_jump2(struct hx_state *hx)
{
	hx->s1 ^= hx->key[hx->m];
	hx->key[hx->m] = u8(hx->s2);
	hx->m ^= hx->v; /* Note: v not s2 (see jump0) */
	hx->m &= hx->key_mask;
	hx->s2 = rol32(hx->s2, 1);

	hx_vdbg(hx, "jump2");
}

void hx_jump3(struct hx_state *hx)
{
	hx->s2 ^= hx->key[hx->m];
	hx->key[hx->m] = u8(hx->s1);
	hx->m ^= hx->s1; /* Note: s1 not v (see jump1) */
	hx->m &= hx->key_mask;
	hx->s1 = ror32(hx->s1, 1);

	hx_vdbg(hx, "jump3");
}

void hx_jump(struct hx_state *hx)
{
	hx->jump_fn(hx);
}

static void hx_jump_any(struct hx_state *hx)
{
	uint32_t j = 1, jumps = hx->key_jumps;

	/* Note: reference alg always jumps at least twice */

	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);

	/* Note: "optimized" alg unwinds and eliminates branches */

	for (;;) {
		if (++j == jumps)
			return;

		hx_jump2(hx);

		if (++j == jumps)
			return;

		hx_jump3(hx);
	}
}

static void hx_jump_opt2(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
}

static void hx_jump_opt3(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
	hx_jump2(hx);
}

static void hx_jump_opt4(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
	hx_jump2(hx);
	hx_jump3(hx);
}

static void hx_jump_opt5(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
	hx_jump2(hx);
	hx_jump3(hx);
	hx_jump2(hx);
}

static void hx_jump_opt6(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
	hx_jump2(hx);
	hx_jump3(hx);
	hx_jump2(hx);
	hx_jump3(hx);
}

static void hx_jump_opt7(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
	hx_jump2(hx);
	hx_jump3(hx);
	hx_jump2(hx);
	hx_jump3(hx);
	hx_jump2(hx);
}

static void hx_jump_opt8(struct hx_state *hx)
{
	hx_vdbg(hx, "start");
	hx_jump0(hx);
	hx_jump1(hx);
	hx_jump2(hx);
	hx_jump3(hx);
	hx_jump2(hx);
	hx_jump3(hx);
	hx_jump2(hx);
	hx_jump3(hx);
}

static void (*hx_jump_fn(int key_jumps))(struct hx_state *hx)
{
	switch (key_jumps) {
	case 2: return hx_jump_opt2;
	case 3: return hx_jump_opt3;
	case 4: return hx_jump_opt4;
	case 5: return hx_jump_opt5;
	case 6: return hx_jump_opt6;
	case 7: return hx_jump_opt7;
	case 8: return hx_jump_opt8;
	}
	return hx_jump_any;
}

uint8_t hx_step_xor(struct hx_state *hx)
{
	uint8_t x = u8(hx->v ^ hx->s1 ^ hx->s2);

	vdbg("x %#x\n", x);

	return x;
}

void hx_step_crc(struct hx_state *hx, uint8_t word)
{
	hx->cs = crc32_byte(hx->cs, word);
	hx->v = rol32(hx->v ^ hx->cs, 1);

	vdbg("cs %#x v %#x\n", hx->cs, hx->v);
}

uint32_t hx_text_crc(struct hx_state *hx)
{
	return ~hx->cs;
}

static uint8_t hx_xor(uint8_t word, uint8_t x)
{
	vdbg("in %#x\n", word);
	word ^= x;
	vdbg("out %#x\n", word);

	return word;

}

void hx_encrypt(struct hx_state *hx,
		uint8_t *in_buf,
		uint8_t *out_buf,
		uint32_t len)
{
	int i;
	uint8_t x;

	dbg("len %u\n", len);

	for (i = 0; i < len; ++i) {
		hx_jump(hx);

		x = hx_step_xor(hx);

		/* plaintext is input */
		hx_step_crc(hx, in_buf[i]);

		out_buf[i] = hx_xor(in_buf[i], x);
	}
}

void hx_decrypt(struct hx_state *hx,
		uint8_t *in_buf,
		uint8_t *out_buf,
		uint32_t len)
{
	int i;
	uint8_t x;

	dbg("len %u\n", len);

	for (i = 0; i < len; ++i) {
		hx_jump(hx);

		x = hx_step_xor(hx);

		out_buf[i] = hx_xor(in_buf[i], x);

		/* plaintext is output */
		hx_step_crc(hx, out_buf[i]);
	}
}
