#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hohha_xor.h"
#include "hohha_util.h"

static void hx_done(struct hx_state *hx, struct hx_state *hx_mask);
static void hx_brut(struct hx_state *hx, struct hx_state *hx_mask,
		    uint8_t *raw_m, uint8_t *raw_x, size_t raw_len);

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
	struct hx_state *hx, *hx_mask;

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

	hx = hx_zalloc(sizeof(*hx) + num_l);

	hx_mask = hx_zalloc(sizeof(*hx_mask) + num_l);
	/* What have we guessed about hx:
	 *   key: mask of bits we have guessed of key
	 *   m: mask of bits we have guessed of v
	 *   v: our guess of initial v
	 *   cs: current rotate left of v
	 *   opt: current jump number
	 */

	hx_init(hx, NULL, num_l, num_j,
		*(uint32_t *)(raw_S),
		*(uint32_t *)(raw_S + 4),
		0);
	hx->v = 0;

	hx_brut(hx, hx_mask, raw_m, raw_x, raw_x_len);

	return 0;
}

static void hx_done(struct hx_state *hx, struct hx_state *hx_mask)
{
	char *out = malloc((hx->key_mask + 1) * 4);

	printf("--------------------------------\n");
	printf("v: %#08x (%#08x)\n", hx_mask->v, hx_mask->cs);

	b64_encode(hx->key, hx->key_mask + 1, out, hx->key_mask + 1);
	printf("k: %s\n", out);

	b64_encode(hx_mask->key, hx->key_mask + 1, out, hx->key_mask + 1);
	printf("k: %s\n", out);

	free(out);
}

static void hx_brut_csum(struct hx_state *hx, struct hx_state *hx_mask,
			 uint8_t *raw_m, uint8_t *raw_x, size_t raw_len)
{
	struct hx_state old_hx = *hx;
	struct hx_state old_hx_mask = *hx_mask;

	uint8_t xor_diff = *raw_m ^ *raw_x ^ hx->v ^ hx->s1 ^ hx->s2;
	uint8_t xor_mask = rol32(hx_mask->m, hx_mask->cs);
	uint8_t xor_clash = xor_diff & xor_mask;
	uint8_t xor_learn = xor_diff & ~xor_mask;

	vdbg("hx_brut_csum\n");

	if (!xor_clash) {
		vdbg("we learn something!\n");
		hx_mask->m |= ror32(xor_mask, hx_mask->cs);
		hx_mask->v |= ror32(xor_learn, hx_mask->cs);
		hx_mask->cs = (hx_mask->cs + 1) & 31;
		hx_mask->opt = 0;

		hx->v ^= xor_learn;

		hx_brut(hx, hx_mask, raw_m + 1, raw_x + 1, raw_len - 1);

		*hx = old_hx;
		*hx_mask = old_hx_mask;
	}
}

static void (*hx_brut_jump_fn(uint32_t j))(struct hx_state *hx)
{
	if (j == 0)
		return hx_jump0;
	if (j == 1)
		return hx_jump1;
	if (!(j & 1))
		return hx_jump2;
	return hx_jump3;
}

static void hx_brut_jump(struct hx_state *hx, struct hx_state *hx_mask,
			 uint8_t *raw_m, uint8_t *raw_x, size_t raw_len)
{
	struct hx_state old_hx = *hx;
	struct hx_state old_hx_mask = *hx_mask;
	uint32_t jump = hx_mask->opt++;

	if (hx_mask->key[hx->m] == 0xff) {
		vdbg("hx_brut_jump again\n");
		hx_brut_jump_fn(jump)(hx);
		hx_brut(hx, hx_mask, raw_m, raw_x, raw_len);
		*hx = old_hx;
	} else {
		vdbg("hx_brut_jump guess m=%u\n", hx->m);
		hx_mask->key[hx->m] = 0xff;
		for (uint32_t x = 0; x <= 0xff; ++x) {
			hx->key[hx->m] = x;
			hx_brut_jump_fn(jump)(hx);
			hx_brut(hx, hx_mask, raw_m, raw_x, raw_len);
			*hx = old_hx;
		}
		hx->key[hx->m] = 0;
	}
	*hx_mask = old_hx_mask;
}

static void hx_brut(struct hx_state *hx, struct hx_state *hx_mask,
		    uint8_t *raw_m, uint8_t *raw_x, size_t raw_len)
{
	vdbg("hx_brut raw_len=%zu\n", raw_len);
	if (!raw_len) {
		hx_done(hx, hx_mask);
		return;
	}

	if (hx_mask->opt == hx->key_jumps) {
		hx_brut_csum(hx, hx_mask, raw_m, raw_x, raw_len);
	} else {
		hx_brut_jump(hx, hx_mask, raw_m, raw_x, raw_len);
	}
}
