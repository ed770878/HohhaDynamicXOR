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

struct hxb_msg {
	uint32_t s1;			/* original s1 */
	uint32_t s2;			/* original s2 */
	uint8_t *mesg;			/* cleartext message */
	uint8_t *ciph;			/* ciphertext message */
	size_t len;			/* length of message */
};

struct hxb_pos {
	size_t idx;			/* current step */
	size_t jmp;			/* current jump */
	struct hx_state hx;		/* running state */
};

struct hxb_ctx {
	size_t key_length;		/* size of key body */
	size_t key_jumps;		/* number of jumps */

	uint8_t *known_key;		/* known key for debugging */
	uint32_t known_v;		/* known key crc */

	uint32_t *ord_m;		/* fixed guessing order */
	size_t *ord_wt;			/* learned weights */
	size_t ord_next;		/* next guess number */
	size_t ord_count;		/* fixed guessing order count */
	size_t ord_depth;		/* fixed guessing order depth */

	uint8_t (*orig_key)[0x100];	/* permutations of 0..256 */
	size_t (*orig_key_wt)[0x100];	/* learned weights */
	size_t *orig_key_num;		/* number of values */
	size_t *orig_key_idx;		/* current permutation index */

	uint32_t *orig_v;		/* permutation of low-byte */
	size_t *orig_v_wt;		/* learned weights */
	size_t orig_v_num;		/* number of values */
	size_t orig_v_idx;		/* current pumutation index */
	uint32_t orig_v_bits;		/* current guess of v */
	uint32_t orig_v_mask;		/* current mask of v */

	size_t count;			/* number of inputs */
	struct hxb_msg **msg;		/* count number of messages */
	struct hxb_pos **pos;		/* count number of positions */

	/* positions need to be saved and restored with each guess */
};

/* --- --- --- --- --- --- --- --- --- */

#define HXB_MAX_FREE (1u << 14)

struct hxb_pos **hxb_save_list[HXB_MAX_FREE];
size_t hxb_save_count;

void hxb_save_free(struct hxb_pos **save, size_t count)
{
	size_t i;

	if (hxb_save_count < HXB_MAX_FREE) {
		hxb_save_list[hxb_save_count++] = save;
		return;
	}

	for (i = 0; i < count; ++i)
		free(save[i]);
	free(save);
}

struct hxb_pos **hxb_save_alloc(size_t count, size_t key_length)
{
	struct hxb_pos **save;
	size_t i;

	if (hxb_save_count)
		return hxb_save_list[--hxb_save_count];

	save = malloc(sizeof(*save) * count);
	for (i = 0; i < count; ++i)
		save[i] = malloc(sizeof(**save) + key_length);

	return save;
}

void *hxb_ctx_save(struct hxb_ctx *ctx)
{
	struct hxb_pos **save = ctx->pos;
	size_t i;

	ctx->pos = hxb_save_alloc(ctx->count, ctx->key_length);
	for (i = 0; i < ctx->count; ++i)
		memcpy(ctx->pos[i], save[i], sizeof(**save) + ctx->key_length);

	return save;
}

void hxb_ctx_restore(struct hxb_ctx *ctx, void *save)
{
	hxb_save_free(ctx->pos, ctx->count);
	ctx->pos = save;
}

/* --- --- --- --- --- --- --- --- --- */

static int hxb_ctx_match_v(struct hxb_ctx *ctx, uint32_t v)
{
	return !((v ^ ctx->orig_v_bits) & ctx->orig_v_mask);
}

static int hxb_ctx_match_key(struct hxb_ctx *ctx, uint8_t *key)
{
	size_t i, g;

	for (i = 0; i < ctx->key_length; ++i) {
		g = ctx->orig_key_idx[i];
		if (~g && key[i] != ctx->orig_key[i][g])
			return 0;
	}

	return 1;
}

static int hxb_ctx_known_key(struct hxb_ctx *ctx)
{
	return ctx->known_key &&
		hxb_ctx_match_v(ctx, ctx->known_v) &&
		hxb_ctx_match_key(ctx, ctx->known_key);
}

static void hxb_ctx_guess_key(struct hxb_ctx *ctx, uint8_t *key)
{
	size_t i, g;

	for (i = 0; i < ctx->key_length; ++i) {
		g = ctx->orig_key_idx[i];
		if (~g)
			key[i] = ctx->orig_key[i][g];
		else
			key[i] = ctx->orig_key[i][0];
	}
}

static void hxb_ctx_guess_key_mask(struct hxb_ctx *ctx, uint8_t *key_mask)
{
	size_t i, g;

	for (i = 0; i < ctx->key_length; ++i) {
		g = ctx->orig_key_idx[i];
		if (~g)
			key_mask[i] = ~0;
		else
			key_mask[i] = 0;
	}
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ctx_show_v(struct hxb_ctx *ctx, FILE *f)
{
	fprintf(f, "v: %#x (%#x)\n", ctx->orig_v_bits, ctx->orig_v_mask);
}

static void hxb_ctx_show_key(struct hxb_ctx *ctx, FILE *f)
{
	size_t data_len = (ctx->key_length * 4 / 3 + 3) & ~3;
	char *data;
	uint8_t *key;

	data = malloc(data_len + 1);
	key = malloc(ctx->key_length);

	hxb_ctx_guess_key(ctx, key);

	b64_encode(key, ctx->key_length, data, data_len + 1);
	fprintf(f, "k: %s\n", data);

	hxb_ctx_guess_key_mask(ctx, key);

	b64_encode(key, ctx->key_length, data, data_len + 1);
	fprintf(f, "m: %s\n", data);

	free(data);
	free(key);
}

static void hxb_ctx_show(struct hxb_ctx *ctx, FILE *f, char *where)
{
	fprintf(f, "--(%s)------------------------------------------\n", where);
	hxb_ctx_show_v(ctx, f);
	hxb_ctx_show_key(ctx, f);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ord_fix(struct hxb_ctx *ctx, uint32_t m)
{
	if (ctx->ord_next != ctx->ord_count) {
		pr("bad fix\n");
		exit(1);
	}

	ctx->ord_m[ctx->ord_count++] = m;
	++ctx->ord_next;
}

static uint32_t hxb_ord_next(struct hxb_ctx *ctx)
{
	return ctx->ord_m[ctx->ord_next++];
}

static void hxb_ord_prev(struct hxb_ctx *ctx)
{
	--ctx->ord_next;
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_hx_init(struct hx_state *hx, struct hxb_ctx *ctx, struct hxb_msg *msg)
{
	hx->jump_fn = hx_jump_fn(ctx->key_jumps);
	hx->key_mask = ctx->key_length - 1;
	hx->key_jumps = ctx->key_jumps;
	hx->s1 = msg->s1;
	hx->s2 = msg->s2;
	hx->m = (msg->s1 >> 24) * (msg->s2 >> 24);
	hx->m &= hx->key_mask;
	hx->v = ctx->orig_v_bits;
	hx->cs = ~0;
	hx->opt = 0;
}

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
	struct hxb_msg *msg;
	struct hxb_pos *pos;
	size_t i;
	int rc = 0;

	hx = malloc(sizeof(*hx) + ctx->key_length);

	for (i = 0; i < ctx->count; ++i) {
		msg = ctx->msg[i];
		pos = ctx->pos[i];

		hxb_hx_init(hx, ctx, msg);
		hxb_ctx_guess_key(ctx, hx->key);

		rc = hxb_hx_check(hx, msg->mesg, msg->ciph, pos->idx);
		if (rc)
			break;
	}

	free(hx);

	return rc;
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_hx_set_key(struct hx_state *hx, uint32_t m, uint8_t x)
{
	hx->key[m] = x;
}

static void hxb_pos_set_key(struct hxb_pos *pos, uint32_t m, uint8_t x)
{
	hxb_hx_set_key(&pos->hx, m, x);
}

static int hxb_ctx_next_key(struct hxb_ctx *ctx, uint32_t m)
{
	size_t i, g;
	uint8_t x;

	g = ++ctx->orig_key_idx[m];

	if (g == ctx->orig_key_num[m]) {
		ctx->orig_key_idx[m] = ~0;
		return -1;
	}

	x = ctx->orig_key[m][g];

	for (i = 0; i < ctx->count; ++i)
		hxb_pos_set_key(ctx->pos[i], m, x);

	return 0;
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_hx_xor_v(struct hx_state *hx, uint32_t v)
{
	hx->v ^= v;
}

static void hxb_pos_xor_v(struct hxb_pos *pos, uint32_t v)
{
	hxb_hx_xor_v(&pos->hx, rol32(v, pos->idx & 31));
}

static void hxb_ctx_xor_v(struct hxb_ctx *ctx, uint32_t v)
{
	size_t i;

	ctx->orig_v_bits ^= v;

	for (i = 0; i < ctx->count; ++i)
		hxb_pos_xor_v(ctx->pos[i], v);
}

static void hxb_ctx_xor_v_mask(struct hxb_ctx *ctx, uint32_t v)
{
	ctx->orig_v_mask ^= v;
}

/* --- --- --- --- --- --- --- --- --- */

static int hxb_pos_done(struct hxb_pos *pos, struct hxb_msg *msg)
{
	return pos->idx == msg->len;
}

static int hxb_ctx_done(struct hxb_ctx *ctx)
{
	size_t i;

	for (i = 0; i < ctx->count; ++i)
		if (!hxb_pos_done(ctx->pos[i], ctx->msg[i]))
			return 0;
	return 1;
}

/* --- --- --- --- --- --- --- --- --- */

static int hxb_pos_want_m(struct hxb_pos *pos, struct hxb_ctx *ctx)
{
	return !~ctx->orig_key_idx[pos->hx.m];
}

static uint32_t hxb_pos_need_m(struct hxb_pos *pos)
{
	return pos->hx.m;
}

static uint32_t hxb_pos_need_v(struct hxb_pos *pos, struct hxb_ctx *ctx)
{
	return ~ctx->orig_v_mask & ror32(pos->hx.key_mask | 0xff, pos->idx & 31);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_pos_jump(struct hxb_pos *pos)
{
	hx_jump_n(&pos->hx, pos->jmp);

	++pos->jmp;
}

static int hxb_pos_step(struct hxb_pos *pos, struct hxb_msg *msg)
{
	size_t i = pos->idx;
	uint8_t mesg_x = msg->mesg[i];
	uint8_t ciph_x = msg->ciph[i];

	vdbg("mesg %#hhx ciph %#hhx xor %#hhx (want %#hhx)\n",
	     mesg_x, ciph_x,
	     hx_step_xor(&pos->hx),
	     mesg_x ^ ciph_x);

	if (hx_step_xor(&pos->hx) != (mesg_x ^ ciph_x))
		return -1;

	hx_step_crc(&pos->hx, mesg_x);

	pos->jmp = 0;
	++pos->idx;

	return 0;
}

static int hxb_pos_adv(struct hxb_pos *pos, struct hxb_msg *msg, struct hxb_ctx *ctx)
{
	int rc;

	vvdbg("start s1 %#x s2 %#x m %u v %#x\n",
	      pos->hx.s1, pos->hx.s2, pos->hx.m, pos->hx.v);

	while (!hxb_pos_done(pos, msg)) {
		if (hxb_pos_need_v(pos, ctx))
			return 0;

		while (pos->jmp < pos->hx.key_jumps) {
			if (hxb_pos_want_m(pos, ctx))
				return 0;

			vvdbg("adv next key[%u] %#hhx\n",
			      pos->hx.m, pos->hx.key[pos->hx.m]);

			hxb_pos_jump(pos);
		}

		rc = hxb_pos_step(pos, msg);
		if (rc)
			return rc;
	}

	return 0;
}

static int hxb_ctx_adv(struct hxb_ctx *ctx)
{
	size_t i;
	int rc;

	for (i = 0; i < ctx->count; ++i) {
		rc = hxb_pos_adv(ctx->pos[i], ctx->msg[i], ctx);
		if (rc)
			return rc;
	}

	return 0;
}

/* --- --- --- --- --- --- --- --- --- */

static size_t hxb_ctx_get_weight(struct hxb_ctx *ctx)
{
	size_t i, wt = 0;

	for (i = 0; i < ctx->count; ++i)
		if (ctx->pos[i]->idx > wt)
			wt = ctx->pos[i]->idx;

	return wt;
}

static void hxb_ctx_weight_key(struct hxb_ctx *ctx, size_t wt)
{
	size_t i, g;

	for (i = 0; i < ctx->key_length; ++i) {
		g = ctx->orig_key_idx[i];
		if (~g && wt > ctx->orig_key_wt[i][g])
			ctx->orig_key_wt[i][g] = wt;
	}
}

static void hxb_ctx_weight_v(struct hxb_ctx *ctx, size_t wt)
{
	size_t i = ctx->orig_v_idx;

	if (wt > ctx->orig_v_wt[i]) {
		ctx->orig_v_wt[i] = wt;
		ctx->orig_v[i] = ctx->orig_v_bits;
	}
}

static void hxb_ctx_weight(struct hxb_ctx *ctx)
{
	size_t wt = hxb_ctx_get_weight(ctx);

	hxb_ctx_weight_key(ctx, wt);
	hxb_ctx_weight_v(ctx, wt);
}

/* --- --- --- --- --- --- --- --- --- */

static size_t hxb_prune_find_key(uint8_t *key, uint8_t tgt, size_t num)
{
	int i;

	for (i = 0; i < num; ++i)
		if (key[i] == tgt)
			return i;

	return num;
}

static size_t hxb_prune_find_v(uint32_t *v, uint32_t tgt, size_t num)
{
	int i;

	for (i = 0; i < num; ++i)
		if (!((v[i] ^ tgt) & 0xff))
			return i;

	return num;
}

static size_t hxb_prune_find_wt(size_t *wt, size_t tgt, size_t num)
{
	size_t i;

	for (i = 0; i < num; ++i)
		if (wt[i] == tgt)
			return i;

	return num;
}

static void hxb_ctx_ord_wt(struct hxb_ctx *ctx)
{
	size_t i;

	memset(ctx->ord_wt, 0, sizeof(*ctx->ord_wt) * ctx->key_length);

	for (i = 0; i < ctx->count; ++i)
		if (hxb_pos_want_m(ctx->pos[i], ctx))
			++ctx->ord_wt[hxb_pos_need_m(ctx->pos[i])];
}

static void hxb_ctx_sort(struct hxb_ctx *ctx)
{
	size_t i;

	for (i = 0; i < ctx->key_length; ++i)
		heap_sort_u8_gt(ctx->orig_key[i],
				 ctx->orig_key_wt[i],
				 0, ctx->orig_key_num[i]);

	heap_sort_u32_gt(ctx->orig_v,
			  ctx->orig_v_wt,
			  0, ctx->orig_v_num);
}

static void hxb_ctx_prune(struct hxb_ctx *ctx)
{
	size_t i, chk, num;
	double f = 1.0;

	for (i = 0; i < ctx->key_length; ++i) {
		num = hxb_prune_find_wt(ctx->orig_key_wt[i], 0,
					ctx->orig_key_num[i]);

		if (num && num != ctx->orig_key_num[i]) {
			dbg("pruned key %zu from %zu to %zu\n",
			   i, ctx->orig_key_num[i], num);

			if (ctx->known_key) {
				chk = hxb_prune_find_key(ctx->orig_key[i],
							 ctx->known_key[i],
							 ctx->orig_key_num[i]);
				if (chk >= num) {
					pr("pruned known key %zu value %#hhx\n",
					   i, ctx->known_key[i]);
					if (chk >= ctx->orig_key_num[i])
						pr("not pruned, just gone!\n");
					else
						pr("pruned with %zu votes\n",
						   ctx->orig_key_wt[i][chk]);
					exit(2);
				}
			}

			f *= num;
			f /= ctx->orig_key_num[i];

			ctx->orig_key_num[i] = num;
		}
	}

	num = hxb_prune_find_wt(ctx->orig_v_wt, 0,
				ctx->orig_v_num);

	if (num && num != ctx->orig_v_num) {
		dbg("pruned v from %zu to %zu\n",
		   ctx->orig_v_num, num);

		if (ctx->known_key) {
			chk = hxb_prune_find_v(ctx->orig_v,
					       ctx->known_v,
					       ctx->orig_v_num);
			if (chk >= num) {
				pr("pruned known key %zu value %#hhx\n",
				   i, ctx->known_key[i]);
				if (chk >= ctx->orig_key_num[i])
					pr("not pruned, just gone!\n");
				exit(2);
			}
		}

		f *= num;
		f /= ctx->orig_v_num;

		ctx->orig_v_num = num;
	}

	dbg("pruned key space by factor of %lg\n", f);
}

static void hxb_ctx_order(struct hxb_ctx *ctx)
{
	size_t i;

	hxb_ctx_ord_wt(ctx);

	for (i = 0; i < ctx->key_length; ++i) {
		ctx->ord_m[i] = i;

		if (ctx->ord_wt[i] < 3 * ctx->count / ctx->key_length)
			ctx->ord_wt[i] = 0;

		ctx->ord_wt[i] |= (0x100 - ctx->orig_key_num[i]) << 16;
	}

	heap_sort_u32_gt(ctx->ord_m,
			 ctx->ord_wt,
			 0, ctx->key_length);

	ctx->ord_count = hxb_prune_find_wt(ctx->ord_wt, 0,
					   ctx->key_length);

	dbg("fixed key order");
	for (i = 0; i < ctx->ord_count; ++i)
		dbg(" %u", ctx->ord_m[i]);
	dbg("\n");
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ctx_brut(struct hxb_ctx *ctx);

static int hxb_ctx_brut_v(struct hxb_ctx *ctx)
{
	void *save;
	size_t i;
	uint32_t need, guess;

	need = 0;
	for (i = 0; i < ctx->count; ++i)
		need |= hxb_pos_need_v(ctx->pos[i], ctx);

	if (!need)
		return 0;

	hxb_ctx_xor_v_mask(ctx, need);

	for (guess = 0; guess <= need; guess = incr32_mask(guess, need)) {
		save = hxb_ctx_save(ctx);
		hxb_ctx_xor_v(ctx, guess);

		hxb_ctx_brut(ctx);

		hxb_ctx_xor_v(ctx, guess);
		hxb_ctx_restore(ctx, save);
	}

	hxb_ctx_xor_v_mask(ctx, need);

	return 1;
}

static void hxb_ctx_brut_m(struct hxb_ctx *ctx)
{
	void *save;
	uint32_t m;

	if (ctx->ord_next < ctx->ord_count) {
		m = hxb_ord_next(ctx);
	} else {
		hxb_ctx_ord_wt(ctx);
		m = max_idx(ctx->ord_wt, ctx->key_length);
		hxb_ord_fix(ctx, m);
	}

	while (!hxb_ctx_next_key(ctx, m)) {
		save = hxb_ctx_save(ctx);

		hxb_ctx_brut(ctx);

		hxb_ctx_restore(ctx, save);
	}

	hxb_ord_prev(ctx);
}

static void hxb_ctx_brut_m_leaf(struct hxb_ctx *ctx)
{
	void *save;
	size_t i;

	ctx->ord_next = ctx->ord_depth;

	for (i = ctx->ord_depth - 1; i < ctx->ord_count; ++i) {
		while (!hxb_ctx_next_key(ctx, ctx->ord_m[i])) {
			save = hxb_ctx_save(ctx);

			hxb_ctx_brut(ctx);

			hxb_ctx_restore(ctx, save);
		}
	}

	ctx->ord_next = ctx->ord_depth - 1;
}

static void hxb_ctx_brut(struct hxb_ctx *ctx)
{
	if (hxb_ctx_adv(ctx)) {
		if (hxb_ctx_known_key(ctx)) {
			hxb_ctx_show(ctx, stderr, "oops");
			pr("oops for v %#x mask %#x\n",
			   ctx->orig_v_bits, ctx->orig_v_mask);
			if (ctx->ord_next) {
				size_t g = ctx->ord_m[ctx->ord_next - 1];
				pr("oops for key %zu val %#hhx\n",
				   g, ctx->known_key[g]);
				pr("guess key %zu val %#hhx\n",
				   g, ctx->orig_key[g][ctx->orig_key_idx[g]]);
			}
			exit(2);
		}
		return;
	}

	if (hxb_dbg_level && hxb_ctx_check(ctx)) {
		hxb_ctx_show(ctx, stderr, "fail");
		exit(2);
	}

	if (done_sigusr1 != seen_sigusr1) {
		done_sigusr1 = seen_sigusr1;
		hxb_ctx_show(ctx, stderr, "info");
	}

	if (ctx->ord_next == ctx->ord_depth) {
		hxb_ctx_weight(ctx);
		return;
	}

	if (hxb_ctx_done(ctx)) {
		hxb_ctx_weight(ctx);
		if (!~ctx->ord_depth)
			hxb_ctx_show(ctx, stdout, "done");
		return;
	}

	if (hxb_ctx_brut_v(ctx))
		return;

	if (1 || ctx->ord_next < ctx->ord_depth - 1)
		hxb_ctx_brut_m(ctx);
	else
		hxb_ctx_brut_m_leaf(ctx);
}

static void hxb_ctx_search(struct hxb_ctx *ctx)
{
	void *save;

	hxb_ctx_xor_v_mask(ctx, 0xff);

	for (ctx->orig_v_idx = 0;
	     ctx->orig_v_idx < ctx->orig_v_num;
	     ++ctx->orig_v_idx) {
		dbg("\rprogress %zu / %zu",
		    ctx->orig_v_idx + 1,
		    ctx->orig_v_num);

		save = hxb_ctx_save(ctx);
		hxb_ctx_xor_v(ctx, ctx->orig_v[ctx->orig_v_idx]);

		hxb_ctx_brut(ctx);

		/* Note: ctx->orig_v[idx] might have changed! */
		hxb_ctx_xor_v(ctx, ctx->orig_v_bits);
		hxb_ctx_restore(ctx, save);
	}
	dbg("\n");

	hxb_ctx_xor_v_mask(ctx, 0xff);
}

static void hxb_ctx_deep(struct hxb_ctx *ctx, size_t cutoff)
{
	if (cutoff > ctx->key_length)
		cutoff = ctx->key_length;

	for (ctx->ord_depth = 1;
	     ctx->ord_depth < cutoff;
	     ++ctx->ord_depth) {
		dbg("search depth %zu\n", ctx->ord_depth);

		memset(ctx->orig_key_wt, 0,
		       sizeof(*ctx->orig_key_wt) * ctx->key_length);

		memset(ctx->orig_v_wt, 0,
		       sizeof(*ctx->orig_v_wt) * 0x100);

		hxb_ctx_search(ctx);
		hxb_ctx_sort(ctx);
		hxb_ctx_prune(ctx);
		hxb_ctx_order(ctx);
	}

	dbg("cutoff reached\n");
	ctx->ord_depth = ~0;
	hxb_ctx_search(ctx);
}

/* --- --- --- --- --- --- --- --- --- */

static void hxb_ctx_read(struct hxb_ctx *ctx, FILE *f)
{
	struct hxb_msg *msg;
	struct hxb_pos *pos;
	size_t i;
	uint8_t raw_S[8];
	char *arg_m;
	char *arg_x;
	size_t raw_m_len;
	size_t raw_x_len;
	int rc;

	for (;;) {
		arg_m = NULL;
		arg_x = NULL;

		rc = fscanf(f, "%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu %ms %ms",
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

		i = ctx->count;

		if (!i) {
			ctx->msg = malloc(sizeof(*ctx->msg));
			ctx->pos = malloc(sizeof(*ctx->pos));
		} else if (is_pow2(i)) {
			ctx->msg = realloc(ctx->msg, sizeof(*ctx->msg) * (i << 1));
			ctx->pos = realloc(ctx->pos, sizeof(*ctx->pos) * (i << 1));
		}

		msg = malloc(sizeof(*msg));

		msg->s1 = leu32(raw_S + 0);
		msg->s2 = leu32(raw_S + 4);
		msg->mesg = malloc(raw_m_len);
		msg->ciph = malloc(raw_x_len);
		msg->len = raw_x_len;

		b64_decode(arg_m, strlen(arg_m), msg->mesg, &raw_m_len);
		b64_decode(arg_x, strlen(arg_x), msg->ciph, &raw_x_len);

		pos = malloc(sizeof(*pos) + ctx->key_length);
		pos->idx = 0;
		pos->jmp = 0;
		hxb_hx_init(&pos->hx, ctx, msg);

		ctx->msg[i] = msg;
		ctx->pos[i] = pos;

		ctx->count = i + 1;

		vdbg("pos[%zu] s1 %#x s2 %#x mesg %s ciph %s\n",
		     i, msg->s1, msg->s2, arg_m, arg_x);

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

	char *arg_f = NULL;
	char *arg_j = NULL;
	char *arg_l = NULL;
	char *arg_h = NULL;
	char *arg_k = NULL;
	char *arg_c = NULL;
	char *arg_e = NULL;

	int opt_r = 0;
	uint32_t num_j = 0;
	uint32_t num_l = 0;
	uint32_t num_h = 0;
	uint8_t *raw_k = NULL;
	size_t raw_k_len = 0;
	uint8_t *raw_e = NULL;
	size_t raw_e_len = 0;
	size_t num_c = 0;

	size_t i, j;

	opterr = 1;
	while ((rc = getopt(argc, argv, "f:j:l:h:k:c:e:rvz")) != -1) {
		switch (rc) {

		case 'f': /* file name: string */
			arg_f = optarg;
			break;

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

		case 'c': /* specify cutoff depth */
			arg_c = optarg;
			break;

		case 'e': /* debug with known key: base64 */
			arg_e = optarg;
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
			"    -c <depth>\n"
			"      Specify cutoff depth for iterative deepening\n"
			"    -r\n"
			"      Randomize key body and checksum\n"
			"    -f <file>\n"
			"      Read known plaintext from file\n"
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

	if (arg_c) {
		unsigned long val;

		errno = 0;
		val = strtoul(arg_c, NULL, 0);
		if (errno || val > SIZE_MAX) {
			fprintf(stderr, "invalid -c '%s'\n", arg_c);
			exit(1);
		}

		num_c = (size_t)val;
	} else {
		num_c = num_l >> 2;
	}

	if (arg_e) {
		rc = b64_decode(arg_e, strlen(arg_e), NULL, &raw_e_len);
		if (rc) {
			fprintf(stderr, "invalid -e '%s'\n", arg_e);
			exit(1);
		}
		if (raw_e_len != num_l) {
			fprintf(stderr, "invalid length -e '%s'\n", arg_e);
			exit(1);
		}

		raw_e = malloc(raw_e_len);

		b64_decode(arg_e, strlen(arg_e), raw_e, &raw_e_len);
	}

	ctx.key_length = num_l;
	ctx.key_jumps = num_j;

	ctx.ord_m = malloc(sizeof(*ctx.ord_m) * ctx.key_length);
	ctx.ord_wt = malloc(sizeof(*ctx.ord_wt) * ctx.key_length);
	ctx.ord_next = 0;
	ctx.ord_count = 0;
	ctx.ord_depth = 0;

	ctx.orig_key = malloc(sizeof(*ctx.orig_key) * ctx.key_length);
	ctx.orig_key_wt = malloc(sizeof(*ctx.orig_key_wt) * ctx.key_length);
	ctx.orig_key_num = malloc(sizeof(*ctx.orig_key_num) * ctx.key_length);
	ctx.orig_key_idx = malloc(sizeof(*ctx.orig_key_idx) * ctx.key_length);

	ctx.orig_v = malloc(sizeof(*ctx.orig_v) * 0x100);
	ctx.orig_v_wt = malloc(sizeof(*ctx.orig_v_wt) * 0x100);
	ctx.orig_v_bits = 0;
	ctx.orig_v_mask = 0;

	ctx.count = 0;
	ctx.msg = NULL;
	ctx.pos = NULL;

	for (i = 0; i < ctx.key_length; ++i) {
		for (j = 0; j < 0x100; ++j)
			ctx.orig_key[i][j] = j;
		ctx.orig_key_num[i] = 0x100;
		ctx.orig_key_idx[i] = ~0;
	}

	if (opt_r) {
		fill_random(ctx.orig_key_wt,
			  sizeof(*ctx.orig_key_wt) * ctx.key_length);
	} else {
		memset(ctx.orig_key_wt, 0,
		       sizeof(*ctx.orig_key_wt) * ctx.key_length);
	}

	if (arg_k) {
		for (i = 0; i < ctx.key_length; ++i) {
			for (j = 0; j < 0x100; ++j)
				if (!~ctx.orig_key_wt[i][j])
					ctx.orig_key_wt[i][j] = 0;
			ctx.orig_key_wt[i][raw_k[i]] = ~0;
		}
	}

	for (j = 0; j < 0x100; ++j)
		ctx.orig_v[j] = j;
	ctx.orig_v_num = 0x100;
	ctx.orig_v_idx = 0;

	if (opt_r) {
		fill_random(ctx.orig_v, sizeof(*ctx.orig_v) * 0x100);
		for (j = 0; j < 0x100; ++j) {
			ctx.orig_v[j] &= ~0xff;
			ctx.orig_v[j] |= j;
		}

		fill_random(ctx.orig_v_wt, sizeof(*ctx.orig_v_wt) * 0x100);
	} else {
		memset(ctx.orig_v_wt, 0, sizeof(*ctx.orig_v_wt) * 0x100);
	}

	if (arg_h) {
		for (j = 0; j < 0x100; ++j)
			if (!~ctx.orig_v_wt[j])
				ctx.orig_v_wt[j] = 0;
		ctx.orig_v_wt[num_h & 0xff] = ~0;
		ctx.orig_v[num_h & 0xff] = num_h;
	}

	if (arg_f) {
		FILE *f = fopen(arg_f, "r");
		if (!f) {
			fprintf(stderr, "invalid -f '%s'\n", arg_f);
			exit(1);
		}
		hxb_ctx_read(&ctx, f);
		fclose(f);
	} else {
		hxb_ctx_read(&ctx, stdin);
	}

	if (arg_e) {
		ctx.known_key = raw_e;
		ctx.known_v = crc32_data(raw_e, raw_e_len);
	} else {
		ctx.known_key = NULL;
		ctx.known_v = 0;
	}

	signal(SIGUSR1, catch_sigusr1);

	hxb_ctx_sort(&ctx);
	hxb_ctx_order(&ctx);

	hxb_ctx_deep(&ctx, num_c);

	return 0;
}
