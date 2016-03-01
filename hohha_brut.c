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

volatile sig_atomic_t seen_sigusr1;
volatile sig_atomic_t done_sigusr1;
static void catch_sigusr1(int sig)
{
	++seen_sigusr1;
}

/* --- --- --- --- --- --- --- --- --- */

struct hxb_pos {
	struct hx_state *hx;		/* running state */
	uint8_t *mesg;			/* cleartext message */
	uint8_t *ciph;			/* ciphertext message */
	size_t len;			/* length of message */
	size_t idx;			/* current step */
	size_t jmp;			/* current jump */
};

struct hxb_ctx {
	size_t sz_key;			/* size of key */
	size_t sz_hx;			/* size of state */
	size_t pos_count;		/* number of positions */
	struct hxb_pos **pos;		/* cipher positions */
	struct hx_state *hx_orig;	/* guessed original state */
	struct hx_state *hx_mask;	/* mask of guessed bits */
};

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ctx_show(struct hxb_ctx *ctx, FILE *f, char *where)
{
	size_t data_len = (ctx->sz_key * 4 / 3 + 3) & ~3;
	char *data = malloc(data_len + 1);
	size_t pos_i;
	struct hxb_pos *pos;

	fprintf(f, "--(%s)------------------------------------------\n", where);
	fprintf(f, "v: %#x (%#x)\n", ctx->hx_orig->v, ctx->hx_mask->v);

	b64_encode(ctx->hx_orig->key, ctx->sz_key, data, data_len + 1);
	fprintf(f, "k: %s\n", data);

	b64_encode(ctx->hx_mask->key, ctx->sz_key, data, data_len + 1);
	fprintf(f, "m: %s\n", data);

	for (pos_i = 0; pos_i < ctx->pos_count; ++pos_i) {
		pos = ctx->pos[pos_i];
		fprintf(f, "pos[%zu]: jmp %zu idx %zu len %zu\n",
			pos_i, pos->jmp, pos->idx, pos->len);
	}

	free(data);
}

/* --- --- --- --- --- --- --- --- --- */

static int hxb_hx_check(struct hx_state *hx, uint8_t *mesg, uint8_t *ciph, size_t len)
{
	size_t i;
	uint8_t mesg_x;
	uint8_t ciph_x;

	for (i = 0; i < len; ++i) {
		hx->jump_fn(hx);

		mesg_x = mesg[i];
		ciph_x = ciph[i];

		if (hx_step_xor(hx) != (mesg_x ^ ciph_x))
			return -1;

		hx_step_crc(hx, mesg_x);
	}

	return 0;
}

static int hxb_ctx_check(struct hxb_ctx *ctx)
{
	struct hx_state *hx;
	struct hxb_pos *pos;
	size_t i;
	int rc = 0;

	hx = malloc(ctx->sz_hx);

	for (i = 0; i < ctx->pos_count; ++i) {
		pos = ctx->pos[i];

		memcpy(hx, ctx->hx_orig, ctx->sz_hx);
		hx->s1 = pos->hx->s1;
		hx->s2 = pos->hx->s2;

		rc = hxb_hx_check(hx, pos->mesg, pos->ciph, pos->idx);
		if (rc)
			break;
	}

	free(hx);

	return rc;
}

/* --- --- --- --- --- --- --- --- --- */

struct hx_state *hxb_hx_dup(struct hx_state *hx, size_t sz_hx)
{
	struct hx_state *dup;

	dup = malloc(sz_hx);
	memcpy(dup, hx, sz_hx);

	return dup;
}

struct hxb_pos *hxb_pos_dup(struct hxb_pos *pos, size_t sz_hx)
{
	struct hxb_pos *dup;

	dup = malloc(sizeof(*dup));
	dup->hx = hxb_hx_dup(pos->hx, sz_hx);
	dup->mesg = pos->mesg;
	dup->ciph = pos->ciph;
	dup->len = pos->len;
	dup->idx = pos->idx;
	dup->jmp = pos->jmp;

	return dup;
}

struct hxb_ctx *hxb_ctx_dup(struct hxb_ctx *ctx)
{
	struct hxb_ctx *dup;
	size_t i;

	dup = malloc(sizeof(*dup));
	dup->pos = malloc(sizeof(*dup->pos) * ctx->pos_count);
	dup->hx_orig = hxb_hx_dup(ctx->hx_orig, ctx->sz_hx);
	dup->hx_mask = hxb_hx_dup(ctx->hx_mask, ctx->sz_hx);
	dup->pos_count = ctx->pos_count;
	dup->sz_key = ctx->sz_key;
	dup->sz_hx = ctx->sz_hx;

	for (i = 0; i < ctx->pos_count; ++i)
		dup->pos[i] = hxb_pos_dup(ctx->pos[i], ctx->sz_hx);

	return dup;
}

/* --- --- --- --- --- --- --- --- --- */

void hxb_hx_free(struct hx_state *hx)
{
	free(hx);
}

void hxb_pos_free(struct hxb_pos *pos)
{
	hxb_hx_free(pos->hx);
	free(pos);
}

void hxb_ctx_free(struct hxb_ctx *ctx)
{
	size_t i;

	for (i = 0; i < ctx->pos_count; ++i)
		hxb_pos_free(ctx->pos[i]);

	hxb_hx_free(ctx->hx_orig);
	hxb_hx_free(ctx->hx_mask);
	free(ctx->pos);
	free(ctx);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_hx_guess_key(struct hx_state *hx, uint32_t m, uint8_t x)
{
	hx->key[m] = x;
}

static void hxb_pos_guess_key(struct hxb_pos *pos, uint32_t m, uint8_t x)
{
	hxb_hx_guess_key(pos->hx, m, x);
}

static void hxb_ctx_guess_key(struct hxb_ctx *ctx, uint32_t m, uint32_t x)
{
	size_t i;

	hxb_hx_guess_key(ctx->hx_orig, m, x);

	for (i = 0; i < ctx->pos_count; ++i)
		hxb_pos_guess_key(ctx->pos[i], m, x);
}

static void hxb_ctx_mask_key(struct hxb_ctx *ctx, uint32_t m)
{
	hxb_hx_guess_key(ctx->hx_mask, m, ~0);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_hx_guess_v(struct hx_state *hx, uint32_t v)
{
	hx->v ^= v;
}

static void hxb_pos_guess_v(struct hxb_pos *pos, uint32_t v)
{
	hxb_hx_guess_v(pos->hx, rol32(v, pos->idx & 31));
}

static void hxb_ctx_guess_v(struct hxb_ctx *ctx, uint32_t v)
{
	size_t i;

	hxb_hx_guess_v(ctx->hx_orig, v);

	for (i = 0; i < ctx->pos_count; ++i)
		hxb_pos_guess_v(ctx->pos[i], v);
}

static void hxb_ctx_mask_v(struct hxb_ctx *ctx, uint32_t v)
{
	ctx->hx_mask->v |= v;
}

/* --- --- --- --- --- --- --- --- --- */

static int hxb_pos_done(struct hxb_pos *pos)
{
	return pos->idx == pos->len;
}

static int hxb_ctx_done(struct hxb_ctx *ctx)
{
	size_t i;

	for (i = 0; i < ctx->pos_count; ++i)
		if (!hxb_pos_done(ctx->pos[i]))
			return 0;
	return 1;
}

/* --- --- --- --- --- --- --- --- --- */

static int hxb_pos_have_m(struct hxb_pos *pos, struct hx_state *mask)
{
	return !!mask->key[pos->hx->m];
}

static uint32_t hxb_pos_need_m(struct hxb_pos *pos)
{
	return pos->hx->m;
}

static uint32_t hxb_pos_need_v(struct hxb_pos *pos, struct hx_state *mask)
{
	return ~mask->v & ror32(pos->hx->key_mask | 0xff, pos->idx & 31);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_pos_jump(struct hxb_pos *pos)
{
	size_t i = pos->idx;

	hx_jump_n(pos->hx, i);
}

static int hxb_pos_step(struct hxb_pos *pos)
{
	size_t i = pos->idx;
	uint8_t mesg_x = pos->mesg[i];
	uint8_t ciph_x = pos->ciph[i];

	if (hx_step_xor(pos->hx) != (mesg_x ^ ciph_x))
		return -1;

	hx_step_crc(pos->hx, mesg_x);

	return 0;
}

static int hxb_pos_adv(struct hxb_pos *pos, struct hx_state *mask)
{
	int rc;

	while (!hxb_pos_done(pos)) {
		if (hxb_pos_need_v(pos, mask))
			return 0;

		while (pos->jmp < pos->hx->key_jumps) {
			if (!hxb_pos_have_m(pos, mask))
				return 0;

			hxb_pos_jump(pos);

			++pos->jmp;
		}

		rc = hxb_pos_step(pos);
		if (rc)
			return rc;

		pos->jmp = 0;
		++pos->idx;
	}

	return 0;
}

static int hxb_ctx_adv(struct hxb_ctx *ctx)
{
	size_t i;
	int rc;

	for (i = 0; i < ctx->pos_count; ++i) {
		rc = hxb_pos_adv(ctx->pos[i], ctx->hx_mask);
		if (rc)
			return rc;
	}

	return 0;
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ctx_brut(struct hxb_ctx *ctx);

static int hxb_ctx_brut_v(struct hxb_ctx *ctx)
{
	struct hxb_ctx *dup;
	size_t i;
	uint32_t need;
	uint32_t guess;

	need = 0;
	for (i = 0; i < ctx->pos_count; ++i)
		need |= hxb_pos_need_v(ctx->pos[i], ctx->hx_mask);

	if (!need)
		return 0;

	for (guess = 0; guess <= need; guess = incr32_mask(guess, need)) {
		dup = hxb_ctx_dup(ctx);
		hxb_ctx_mask_v(dup, need);
		hxb_ctx_guess_v(dup, guess);

		hxb_ctx_brut(dup);

		hxb_ctx_free(dup);
	}

	return 1;
}

static int hxb_ctx_brut_m(struct hxb_ctx *ctx)
{
	struct hxb_ctx *dup;
	size_t i;
	uint32_t need;
	uint32_t guess;

	for (i = 0; i < ctx->pos_count; ++i) {
		if (hxb_pos_have_m(ctx->pos[i], ctx->hx_mask))
			continue;

		/* TODO: count needs, sort by constraint */

		need = hxb_pos_need_m(ctx->pos[i]);

		for (guess = 0; guess <= 0xff; ++guess) {
			dup = hxb_ctx_dup(ctx);
			hxb_ctx_mask_key(dup, need);
			hxb_ctx_guess_key(dup, need, guess);

			hxb_ctx_brut(dup);

			hxb_ctx_free(dup);
		}
	}

	return 1;
}

static void hxb_ctx_brut(struct hxb_ctx *ctx)
{
	if (hxb_ctx_adv(ctx))
		return;

	if (hxb_dbg_level && hxb_ctx_check(ctx)) {
		hxb_ctx_show(ctx, stderr, "fail");
		exit(2);
	}

	if (done_sigusr1 != seen_sigusr1) {
		done_sigusr1 = seen_sigusr1;
		hxb_ctx_show(ctx, stderr, "info");
	}

	if (hxb_ctx_done(ctx)) {
		hxb_ctx_show(ctx, stdout, "done");
		return;
	}

	if (hxb_ctx_brut_v(ctx))
		return;

	if (hxb_ctx_brut_m(ctx))
		return;

	pr("Unreachable %s:%d\n", __FILE__, __LINE__);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ctx_read(struct hxb_ctx *ctx)
{
	struct hxb_pos *pos;
	size_t pos_i;
	uint8_t raw_S[8];
	char *arg_m;
	char *arg_x;
	size_t raw_m_len;
	size_t raw_x_len;
	int rc;

	for (;;) {
		arg_m = NULL;
		arg_x = NULL;

		rc = scanf("%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %ms %ms",
			   &raw_S[0], &raw_S[1], &raw_S[2], &raw_S[3],
			   &raw_S[4], &raw_S[5], &raw_S[6], &raw_S[7],
			   &arg_m, &arg_x);

		if (rc != 10)
			goto err;

		if (b64_decode(arg_m, strlen(arg_m), NULL, &raw_m_len))
			goto err;

		if (b64_decode(arg_x, strlen(arg_x), NULL, &raw_x_len))
			goto err;

		if (raw_m_len != raw_x_len)
			goto err;

		pos_i = ctx->pos_count;

		if (!pos_i) {
			ctx->pos = malloc(sizeof(*ctx->pos));
		} else if (is_pow2(pos_i)) {
			ctx->pos = realloc(ctx->pos, sizeof(*ctx->pos)
					   * (pos_i << 1));
		}

		pos = malloc(sizeof(*pos));
		pos->hx = hxb_hx_dup(ctx->hx_orig, ctx->sz_hx);
		pos->hx->s1 = leu32(raw_S + 0);
		pos->hx->s2 = leu32(raw_S + 4);
		pos->hx->m = (pos->hx->s1 >> 24) * (pos->hx->s2 >> 24);
		pos->mesg = malloc(raw_m_len);
		pos->ciph = malloc(raw_x_len);
		pos->len = raw_x_len;
		pos->idx = 0;
		pos->jmp = 0;

		b64_decode(arg_m, strlen(arg_m), pos->mesg, &raw_m_len);
		b64_decode(arg_x, strlen(arg_x), pos->ciph, &raw_x_len);

		ctx->pos[pos_i] = pos;
		ctx->pos_count = pos_i + 1;

		free(arg_m);
		free(arg_x);
	}

	return;
err:
	free(arg_m);
	free(arg_x);
}

/* --- --- --- --- --- --- --- --- --- */

int main(int argc, char **argv)
{
	struct hxb_ctx ctx;

	int rc, errflg = 0;

	char *arg_j = NULL;
	char *arg_l = NULL;
	char *arg_h = NULL;
	char *arg_k = NULL;

	int opt_r = 0;
	uint32_t num_j = 0;
	uint32_t num_l = NULL;
	uint32_t num_h = NULL;
	uint8_t *raw_k = NULL;
	size_t raw_k_len = 0;

	opterr = 1;
	while ((rc = getopt(argc, argv, "j:l:h:k:rvz")) != -1) {
		switch (rc) {

		case 'j': /* key jumps: numeric */
			arg_j = optarg;
			break;
		case 'l': /* key length: numeric */
			arg_l = optarg;
			break;

		case 'h': /* initialize v: numeric */
			arg_h = optarg;
			break;

		case 'k': /* initialize key: base64 */
			arg_k = optarg;
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

	if (!arg_j || !arg_l) {
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
			"  Options:\n"
			"    -j <jumps>\n"
			"      Key jumps (numeric) (required)\n"
			"    -l <length>\n"
			"      Key length (numeric) (required)\n"
			"    -h <check>\n"
			"      Initialize key checksum (numeric)\n"
			"    -k <body>\n"
			"      Initialize key body (base64)\n"
			"    -r\n"
			"      Randomize key body and checksum\n"
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

	if (arg_h) {
		unsigned long val;

		errno = 0;
		val = strtoul(arg_h, NULL, 0);
		if (errno || val > UINT32_MAX) {
			fprintf(stderr, "invalid -h '%s'\n", arg_h);
			exit(1);
		}

		num_h = (uint32_t)val;
	}

	if (arg_k) {
		rc = b64_decode(arg_k, strlen(arg_k), NULL, &raw_k_len);
		if (rc) {
			fprintf(stderr, "invalid -k '%s'\n", arg_k);
			exit(1);
		}
		if (raw_k_len != num_l) {
			fprintf(stderr, "invalid length -k '%s'\n", arg_k);
			exit(1);
		}

		raw_k = malloc(raw_k_len);

		b64_decode(arg_k, strlen(arg_k), raw_k, &raw_k_len);
	}

	ctx.sz_key = num_l;
	ctx.sz_hx = sizeof(*ctx.hx_orig) + ctx.sz_key;
	ctx.pos_count = 0;
	ctx.pos = NULL;
	ctx.hx_orig = malloc(ctx.sz_hx);
	ctx.hx_mask = malloc(ctx.sz_hx);

	memset(ctx.hx_orig, 0, ctx.sz_hx);
	memset(ctx.hx_mask, 0, ctx.sz_hx);

	if (opt_r)
		getrandom(ctx.hx_orig, ctx.sz_hx, 0);
	if (arg_k)
		memcpy(ctx.hx_orig->key, raw_k, raw_k_len);

	ctx.hx_orig->jump_fn = hx_jump_fn(num_j);
	ctx.hx_orig->key_mask = num_l - 1;
	ctx.hx_orig->key_jumps = num_j;
	ctx.hx_orig->s1 = 0;
	ctx.hx_orig->s2 = 0;
	ctx.hx_orig->m = 0;
	ctx.hx_orig->cs = ~0;
	ctx.hx_orig->opt = 0;

	if (!opt_r)
		ctx.hx_orig->v = 0;
	if (arg_h)
		ctx.hx_orig->v = num_h;

	hxb_ctx_read(&ctx);

	signal(SIGUSR1, catch_sigusr1);

	hxb_ctx_brut(&ctx);

	return 0;
}

