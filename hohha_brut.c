#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hohha_xor.h"
#include "hohha_util.h"

static int hxb_dbg_level;
static size_t hxb_ebt_idx = SIZE_MAX;
static size_t hxb_ebt_jmp = SIZE_MAX;

volatile sig_atomic_t seen_sigusr1;
volatile sig_atomic_t done_sigusr1;
static void catch_sigusr1(int sig)
{
	++seen_sigusr1;
}

struct hxb_state {
	size_t sz_key;			/* size of key */
	size_t sz_hx;			/* size of state */
	struct hx_state *hx;		/* running state */
	struct hx_state *hx_orig;	/* guessed original state */
	struct hx_state *hx_mask;	/* mask of guessed bits */
	uint8_t *mesg;			/* cleartext message */
	uint8_t *ciph;			/* ciphertext message */
	size_t len;			/* length of message */
	size_t idx;			/* current step */
	size_t jmp;			/* current jump */
};

static void hxb_guess_key(struct hxb_state *hxb, uint32_t m, uint8_t x)
{
	hxb->hx->key[m] = x;
	hxb->hx_orig->key[m] = x;
}

static void hxb_mask_key(struct hxb_state *hxb, uint32_t m, uint8_t x)
{
	hxb->hx_mask->key[m] = x;
}

static int hxb_have_key(struct hxb_state *hxb, uint32_t m)
{
	return hxb->hx_mask->key[m];
}

static uint8_t hxb_step_xor(struct hxb_state *hxb)
{
	return hxb->mesg[hxb->idx] ^ hxb->ciph[hxb->idx];
}

static uint32_t hxb_mask_v(struct hxb_state *hxb)
{
	return rol32(hxb->hx_mask->v, hxb->idx & 31);
}

static void hxb_learn_v(struct hxb_state *hxb, uint32_t mask, uint32_t xor)
{
	hxb->hx->v ^= xor;
	hxb->hx_orig->v ^= ror32(xor, hxb->idx & 31);
	hxb->hx_mask->v |= ror32(mask, hxb->idx & 31);
}

static void hxb_step_crc(struct hxb_state *hxb)
{
	hx_step_crc(hxb->hx, hxb->mesg[hxb->idx]);
}

static void hxb_jump(struct hxb_state *hxb, uint32_t jmp)
{
	uint32_t j0 = !!(jmp & 1);
	uint32_t j1 = !!(jmp & ~1);

	switch (j0 | (j1 << 1)) {
	case 0: hx_jump0(hxb->hx); break;
	case 1: hx_jump1(hxb->hx); break;
	case 2: hx_jump2(hxb->hx); break;
	case 3: hx_jump3(hxb->hx);
	}
}

static int hxb_interesting(struct hxb_state *hxb)
{
	return hxb->idx < 10 || hxb->len - hxb->idx < 10;
}

static void hx_done(FILE *f, char *note, struct hxb_state *hxb);
static void hx_brut(struct hxb_state *hxb);

static void *hx_zalloc(size_t size)
{
	void *x;

	x = malloc(size);
	if (x)
		memset(x, 0, size);

	return x;
}

int main(int argc, char **argv)
{
	struct hxb_state hxb;

	int rc, errflg = 0;

	char *arg_j = NULL;
	char *arg_l = NULL;
	char *arg_S = NULL;
	char *arg_m = NULL;
	char *arg_x = NULL;

	int opt_r = 0;
	uint32_t num_j = 0;
	uint32_t num_l = NULL;
	uint8_t *raw_S = NULL;
	uint8_t *raw_m = NULL;
	size_t raw_m_len = 0;
	uint8_t *raw_x = NULL;
	size_t raw_x_len = 0;

	opterr = 1;
	while ((rc = getopt(argc, argv, "j:l:S:m:x:rvz")) != -1) {
		switch (rc) {

		case 'j': /* key jumps: numeric */
			arg_j = optarg;
			break;
		case 'l': /* key length: numeric */
			arg_l = optarg;
			break;
		case 'S': /* salt: eight numeric */
			arg_S = optarg;
			break;
		case 'm': /* plaintext: base64 */
			arg_m = optarg;
			break;
		case 'x': /* plaintext: base64 */
			arg_x = optarg;
			break;

		case 'r': /* randomize key */
			opt_r = 1;
			break;

		case 'v': /* increase verbosity */
			++hohha_dbg_level;
			break;
		case 'z': /* increase debugging */
			++hxb_dbg_level;
			break;

		case ':':
		case '?':
			++errflg;
		}
	}

	if (!arg_j || !arg_l || !arg_S || !arg_m || !arg_x) {
		fprintf(stderr, "missing one of the required options\n");
		++errflg;
	}

	if (optind != argc) {
		fprintf(stderr, "error: trailing arguments... %s\n", argv[optind]);
		++errflg;
	}

	if (errflg) {
		fprintf(stderr,
			"usage: %s <options> [-v]\n"
			"\n"
			"  Following options must be specified:\n"
			"    -j <jumps>\n"
			"      Key jumps (numeric)\n"
			"    -l <length>\n"
			"      Key length (numeric)\n"
			"    -S <salt>\n"
			"      Key salt (eight numeric)\n"
			"    -m <msg>\n"
			"      Plaintext message (base64)\n"
			"    -x <msg>\n"
			"      Ciphertext message (base64)\n"
			"\n"
			"  -v\n"
			"      Increase debug verbosity (may be repeated)\n"
			"  -z\n"
			"      Increase debug assertions (may be repeated)\n"
			"\n",
			argv[0]);
		exit(2);
	}

	{ /* arg_j */
		unsigned long val;

		errno = 0;
		val = strtoul(arg_j, NULL, 0);
		if (errno || val > UINT32_MAX) {
			fprintf(stderr, "invalid -j '%s'\n", arg_j);
			exit(1);
		}

		num_j = (uint32_t)val;
	}

	{ /* arg_l */
		unsigned long val;

		errno = 0;
		val = strtoul(arg_l, NULL, 0);
		if (errno || val > UINT32_MAX) {
			fprintf(stderr, "invalid -l '%s'\n", arg_l);
			exit(1);
		}

		num_l = (uint32_t)val;
	}

	{ /* arg_s */
		raw_S = malloc(8);

		rc = sscanf(arg_S, "%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu\n",
		       &raw_S[0], &raw_S[1], &raw_S[2], &raw_S[3],
		       &raw_S[4], &raw_S[5], &raw_S[6], &raw_S[7]);
		if (rc != 8) {
			fprintf(stderr, "invalid -S '%s'\n", arg_S);
			exit(1);
		}
	}

	{ /* arg_m */
		size_t sz;

		rc = b64_decode(arg_m, strlen(arg_m), NULL, &sz);
		if (rc) {
			fprintf(stderr, "invalid -m '%s'\n", arg_m);
			exit(1);
		}

		raw_m = malloc(sz);
		raw_m_len = sz;

		b64_decode(arg_m, strlen(arg_m), raw_m, &raw_m_len);
	}

	{ /* arg_x */
		size_t sz;

		rc = b64_decode(arg_x, strlen(arg_x), NULL, &sz);
		if (rc) {
			fprintf(stderr, "invalid -m '%s'\n", arg_x);
			exit(1);
		}

		raw_x = malloc(sz);
		raw_x_len = sz;

		b64_decode(arg_x, strlen(arg_x), raw_x, &raw_x_len);
	}

	if (raw_m_len != raw_x_len) {
		fprintf(stderr, "messages have different lengths (%zu, %zu)\n",
			raw_m_len, raw_x_len);
		exit(1);
	}

	hxb.sz_key = num_l;
	hxb.sz_hx = sizeof(*hxb.hx) + hxb.sz_key;
	hxb.hx = hx_zalloc(hxb.sz_hx);
	hxb.hx_orig = hx_zalloc(hxb.sz_hx);
	hxb.hx_mask = hx_zalloc(hxb.sz_hx);
	hxb.mesg = raw_m;
	hxb.ciph = raw_x;
	hxb.len = raw_x_len;
	hxb.idx = 0;
	hxb.jmp = 0;

	if (opt_r)
		getrandom(hxb.hx, hxb.sz_hx, 0);

	hx_init(hxb.hx, NULL, num_l, num_j,
		*(uint32_t *)(raw_S),
		*(uint32_t *)(raw_S + 4),
		0);

	if (!opt_r)
		hxb.hx->v = 0;

	*hxb.hx_orig = *hxb.hx;

	signal(SIGUSR1, catch_sigusr1);

	hx_brut(&hxb);

	return 0;
}

static void hx_done(FILE *f, char *note, struct hxb_state *hxb)
{
	size_t out_len = (hxb->sz_key * 4 / 3 + 3) & ~3;
	char *out = malloc(out_len + 1);

	fprintf(f, "--%s------------------------------\n", note);

	fprintf(f, "v: %#08x (%#08x)\n", hxb->hx_orig->v, hxb->hx_mask->v);

	b64_encode(hxb->hx_orig->key, hxb->sz_key, out, out_len + 1);
	fprintf(f, "k: %s\n", out);

	b64_encode(hxb->hx_mask->key, hxb->sz_key, out, out_len + 1);
	fprintf(f, "m: %s\n", out);

	free(out);
}

static void hxb_check(struct hxb_state *hxb, char *where)
{
	struct hx_state *hx;
	uint8_t *ciph;
	size_t i;

	if (!hxb_dbg_level)
		return;

	hx = malloc(hxb->sz_hx);
	ciph = malloc(hxb->idx);

	memcpy(hx, hxb->hx_orig, hxb->sz_hx);
	hx_encrypt(hx, hxb->mesg, ciph, hxb->idx);

	if (memcmp(ciph, hxb->ciph, hxb->idx)) {
		hx_done(stderr, where, hxb);
		fprintf(stderr, "current jump %zu at %zu of %zu\n",
			hxb->jmp, hxb->idx, hxb->len);
		hohha_dbg_level= ~0;
		memcpy(hx, hxb->hx_orig, hxb->sz_hx);
		hx_encrypt(hx, hxb->mesg, ciph, hxb->idx);
		for (i = 0; i < hxb->idx; ++i)
			if (ciph[i] != hxb->ciph[i])
				break;
		fprintf(stderr, "failed at idx %zu xor %#04hhx\n",
			i, ciph[i] ^ hxb->ciph[i]);
		exit(1);
	}

	free(hx);
	free(ciph);
}


static void hx_brut_step(struct hxb_state *hxb)
{
	struct hx_state old_hx = *hxb->hx;
	struct hx_state old_hx_orig = *hxb->hx_orig;
	struct hx_state old_hx_mask = *hxb->hx_mask;

	hxb_check(hxb, "#step#A#");

	uint8_t xor_oops = hxb_step_xor(hxb) ^ hx_step_xor(hxb->hx);
	uint8_t xor_mask = hxb_mask_v(hxb);
	uint8_t xor_clash = xor_oops & xor_mask;
	uint8_t xor_learn = xor_oops & ~xor_mask;

	vdbg("xor_oops %#04hhx\n", xor_oops);
	vdbg("xor_mask %#04hhx\n", xor_mask);
	vdbg("xor_clash %#04hhx\n", xor_clash);
	vdbg("xor_learn %#04hhx\n", xor_learn);

	if (!xor_clash) {
		if (hxb_interesting(hxb))
			dbg("proceed at %zu of %zu\n", hxb->idx, hxb->len);

		hxb_learn_v(hxb, 0xff, xor_learn);
		hxb_step_crc(hxb);
		++hxb->idx;
		hxb->jmp = 0;

		hx_brut(hxb);

		--hxb->idx;
		hxb->jmp = hxb->hx->key_jumps;
		*hxb->hx = old_hx;
		*hxb->hx_orig = old_hx_orig;
		*hxb->hx_mask = old_hx_mask;
	}

	if (hxb_interesting(hxb))
		dbg("backtrack at %zu of %zu\n", hxb->idx, hxb->len);

	hxb_check(hxb, "#step#B#");
}

static void hx_brut_jump_next(struct hxb_state *hxb)
{
	struct hx_state old_hx = *hxb->hx;
	size_t m = hxb->hx->m;
	uint32_t j = hxb->jmp++;
	uint32_t k = hxb->hx->key[m];

	hxb_check(hxb, "#jump#A#");

	if (hxb_have_key(hxb, m)) {
		if (hxb_interesting(hxb))
			dbg("jump %u at %zu of %zu existing key[%zu]\n",
			    j, hxb->idx, hxb->len, m);

		hxb_jump(hxb, j);

		hx_brut(hxb);

		*hxb->hx = old_hx;

		hxb_check(hxb, "#jump#B#");
	} else {
		hxb_mask_key(hxb, m, ~0);

		for (uint32_t x = hxb->hx->key[m]; x <= 0xff; ++x) {
			if (hxb_interesting(hxb))
				dbg("jump %u at %zu of %zu new key[%zu]=%#04x\n",
				     j, hxb->idx, hxb->len, m, x);

			hxb_guess_key(hxb, m, k + x);
			hxb_jump(hxb, j);

			hx_brut(hxb);

			*hxb->hx = old_hx;
		}

		hxb_mask_key(hxb, m, 0);

		hxb_check(hxb, "#jump#C#");
	}

	if (hxb_interesting(hxb))
		dbg("backtrack jump %u at %zu of %zu\n",
		    j, hxb->idx, hxb->len);

	hxb->jmp = j;
	hxb->hx->key[m] = k;
}

static void hx_brut_jump(struct hxb_state *hxb)
{
	struct hx_state old_hx = *hxb->hx;
	struct hx_state old_hx_orig = *hxb->hx_orig;
	struct hx_state old_hx_mask = *hxb->hx_mask;
	uint32_t m_mask, v_mask, v_learn;

	m_mask = hxb->hx->key_mask;
	v_mask = m_mask & ~hxb_mask_v(hxb);

	if (!v_mask || !(hxb->jmp & 1) == !(hxb->jmp & ~1)) {
		hx_brut_jump_next(hxb);
	} else {
		for(v_learn = 0; v_learn <= m_mask; ++v_learn) {
			if (v_learn & ~v_mask)
				continue;

			hxb_learn_v(hxb, v_mask, v_learn);

			/* try the most constrained: key[m] chosen */
			if (hxb_have_key(hxb, (hxb->hx->m ^ hxb->hx->v) & m_mask))
				hx_brut_jump_next(hxb);

			*hxb->hx = old_hx;
			*hxb->hx_orig = old_hx_orig;
			*hxb->hx_mask = old_hx_mask;
		}
		for(v_learn = 0; v_learn <= m_mask; ++v_learn) {
			if (v_learn & ~v_mask)
				continue;

			hxb_learn_v(hxb, v_mask, v_learn);

			/* try the rest: key[m] not chosen */
			if (!hxb_have_key(hxb, (hxb->hx->m ^ hxb->hx->v) & m_mask))
				hx_brut_jump_next(hxb);

			*hxb->hx = old_hx;
			*hxb->hx_orig = old_hx_orig;
			*hxb->hx_mask = old_hx_mask;
		}
	}
}

static void hx_brut(struct hxb_state *hxb)
{
	if (done_sigusr1 != seen_sigusr1) {
		done_sigusr1 = seen_sigusr1;
		hx_done(stderr, "progress", hxb);
		fprintf(stderr, "current jump %zu at %zu of %zu\n",
			hxb->jmp, hxb->idx, hxb->len);
		fprintf(stderr, "backtrack jump %zu at %zu of %zu\n",
			hxb_ebt_jmp, hxb_ebt_idx, hxb->len);
		hxb_ebt_idx = SIZE_MAX;
		hxb_ebt_jmp = SIZE_MAX;
	}

	if (hxb->idx < hxb->len) {
		if (hxb->jmp < hxb->hx->key_jumps)
			hx_brut_jump(hxb);
		else
			hx_brut_step(hxb);
	} else {
		hx_done(stdout, "done----", hxb);
	}

	if (hxb->idx < hxb_ebt_idx) {
		hxb_ebt_idx = hxb->idx;
		hxb_ebt_jmp = hxb->jmp;
	} else if (hxb->idx == hxb_ebt_idx) {
		if (hxb->jmp < hxb_ebt_jmp)
			hxb_ebt_jmp = hxb->jmp;
	}
}
