#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hohha_xor.h"
#include "hohha_util.h"

static void hx_done(struct hx_state *hx_orig,
		    struct hx_state *hx_mask);

static void hx_brut(struct hx_state *hx,
		    struct hx_state *hx_orig,
		    struct hx_state *hx_mask,
		    uint8_t *raw_m, uint8_t *raw_x,
		    size_t raw_idx, size_t raw_len);

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
	struct hx_state *hx, *hx_orig, *hx_mask;

	int rc, errflg = 0;

	char *arg_j = NULL;
	char *arg_l = NULL;
	char *arg_S = NULL;
	char *arg_m = NULL;
	char *arg_x = NULL;

	uint32_t num_j = 0;
	uint32_t num_l = NULL;
	uint8_t *raw_S = NULL;
	uint8_t *raw_m = NULL;
	size_t raw_m_len = 0;
	uint8_t *raw_x = NULL;
	size_t raw_x_len = 0;

	opterr = 1;
	while ((rc = getopt(argc, argv, "j:l:S:m:x:v")) != -1) {
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

		case 'v': /* increase verbosity */
			++hohha_dbg_level;
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

	/* Running values of hx */
	hx = hx_zalloc(sizeof(*hx) + num_l);

	hx_init(hx, NULL, num_l, num_j,
		*(uint32_t *)(raw_S),
		*(uint32_t *)(raw_S + 4),
		0);
	hx->v = 0;

	/* Guessed original values of hx */
	hx_orig = hx_zalloc(sizeof(*hx_mask) + num_l);

	*hx_orig = *hx;

	/* Mask of guessed values of hx */
	hx_mask = hx_zalloc(sizeof(*hx_mask) + num_l);

	/* Search for a solution */
	hx_brut(hx, hx_orig, hx_mask,
		raw_m, raw_x, 0, raw_x_len);

	return 0;
}

static void hx_done(struct hx_state *hx_orig,
		    struct hx_state *hx_mask)
{
	size_t key_len = hx_orig->key_mask + 1;
	size_t out_len = (key_len * 4 / 3 + 3) & ~3;
	char *out = malloc(out_len + 1);

	printf("--------------------------------\n");

	printf("v: %#08x (%#08x)\n", hx_orig->v, hx_mask->v);

	b64_encode(hx_orig->key, key_len, out, out_len + 1);
	printf("k: %s\n", out);

	b64_encode(hx_mask->key, key_len, out, out_len + 1);
	printf("m: %s\n", out);

	free(out);
}

static void hx_brut_step(struct hx_state *hx,
			 struct hx_state *hx_orig,
			 struct hx_state *hx_mask,
			 uint8_t *raw_m, uint8_t *raw_x,
			 size_t raw_idx, size_t raw_len)
{
	struct hx_state old_hx = *hx;
	struct hx_state old_hx_orig = *hx_orig;
	struct hx_state old_hx_mask = *hx_mask;

	/* What bits are different from the solution? */
	uint8_t xor_diff = raw_m[raw_idx] ^ raw_x[raw_idx] ^ hx_step_xor(hx);

	/* What bits are not allowed to be different? */
	uint8_t xor_mask = rol32(hx_mask->v, raw_idx & 31);

	/* These bits clash: they are not allowed to be different */
	uint8_t xor_clash = xor_diff & xor_mask;
	/* These bits learn: update the guess to match the solution */
	uint8_t xor_learn = xor_diff & ~xor_mask;

	vdbg("xor_diff %#04hhx\n", xor_diff);
	vdbg("xor_mask %#04hhx\n", xor_mask);
	vdbg("xor_clash %#04hhx\n", xor_clash);
	vdbg("xor_learn %#04hhx\n", xor_learn);

	if (!xor_clash) {
		if (raw_idx < 10 || raw_len - raw_idx < 10)
		dbg("proceed at %zu of %zu\n", raw_idx, raw_len);

		/* Correct the state and update the guess */
		hx->v ^= xor_learn;
		hx_orig->v |= ror32(xor_learn, raw_idx & 31);
		hx_mask->v |= ror32(0xff, raw_idx & 31);

		/* Update the state by taking the step */
		hx_mask->key_jumps = 0;
		hx_step_crc(hx, raw_m[raw_idx]);

		/* Proceed to the next step */
		hx_brut(hx, hx_orig, hx_mask,
			raw_m, raw_x,
			raw_idx + 1, raw_len);

		/* Restore the previous state */
		*hx = old_hx;
		*hx_orig = old_hx_orig;
		*hx_mask = old_hx_mask;
	}

	if (raw_idx < 10 || raw_len - raw_idx < 10)
	dbg("backtrack at %zu of %zu\n", raw_idx, raw_len);
}

static void hx_jump_n(struct hx_state *hx, uint32_t jump_n)
{
	uint32_t j0 = !!(jump_n & 1);
	uint32_t j1 = !!(jump_n & ~1);

	switch (j0 | (j1 << 1)) {
	case 0: hx_jump0(hx); break;
	case 1: hx_jump1(hx); break;
	case 2: hx_jump2(hx); break;
	case 3: hx_jump3(hx);
	}
}

static void hx_brut_jump(struct hx_state *hx,
			 struct hx_state *hx_orig,
			 struct hx_state *hx_mask,
			 uint8_t *raw_m, uint8_t *raw_x,
			 size_t raw_idx, size_t raw_len)
{
	struct hx_state old_hx = *hx;
	uint32_t jump_n = hx_mask->key_jumps++;
	uint32_t m = hx->m;

	if (hx_mask->key[m] == 0xff) {
		if (raw_idx < 10 || raw_len - raw_idx < 10)
		dbg("jump %u at %zu of %zu existing key[%u]\n",
		     jump_n, raw_idx, raw_len, m);

		/* Update the state by taking the jump */
		hx_jump_n(hx, jump_n);

		/* Proceed to the next step */
		hx_brut(hx, hx_orig, hx_mask,
			raw_m, raw_x,
			raw_idx, raw_len);

		/* Restore the previous state */
		*hx = old_hx;
	} else {
		/* We will be making a guess for this m */
		hx_mask->key[m] = 0xff;

		for (uint32_t x = 0; x <= 0xff; ++x) {
			if (raw_idx < 10 || raw_len - raw_idx < 10)
			dbg("jump %u at %zu of %zu with guess key[%u]=%#04x\n",
			     jump_n, raw_idx, raw_len, m, x);

			/* Make a guess for this m */
			hx->key[m] = x;
			hx_orig->key[m] = x;

			/* Update the state by taking the jump */
			hx_jump_n(hx, jump_n);

			/* Proceed to the next step */
			hx_brut(hx, hx_orig, hx_mask,
				raw_m, raw_x,
				raw_idx, raw_len);

			/* Restore the previous state */
			*hx = old_hx;
		}

		/* Remove the guess for this m */
		hx->key[hx->m] = 0;
		hx_orig->key[m] = 0;
		hx_mask->key[m] = 0;
	}

	if (raw_idx < 10 || raw_len - raw_idx < 10)
	dbg("backtrack jump %u at %zu of %zu\n",
	     jump_n, raw_idx, raw_len);
}

static void hx_brut(struct hx_state *hx,
		    struct hx_state *hx_orig,
		    struct hx_state *hx_mask,
		    uint8_t *raw_m, uint8_t *raw_x,
		    size_t raw_idx, size_t raw_len)
{
	if (raw_idx == raw_len) {
		hx_done(hx_orig, hx_mask);
		return;
	}

	if (hx_mask->key_jumps == hx->key_jumps) {
		hx_brut_step(hx, hx_orig, hx_mask,
			     raw_m, raw_x,
			     raw_idx, raw_len);
	} else {
		hx_brut_jump(hx, hx_orig, hx_mask,
			     raw_m, raw_x,
			     raw_idx, raw_len);
	}
}
