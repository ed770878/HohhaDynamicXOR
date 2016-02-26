#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hohha_xor.h"
#include "hohha_util.h"

uint32_t get_key_jumps(void *raw)
{
	return *((uint8_t *)(raw));
}

uint8_t *get_key_salt(void *raw)
{
	return (uint8_t *)(raw + 3);
}

uint32_t get_key_len(void *raw)
{
	return *((uint16_t *)(raw + 1));
}

uint8_t *get_key_body(void *raw)
{
	return (uint8_t *)(raw + 11);
}

int main(int argc, char **argv)
{
	struct hx_state *hx;

	int rc, errflg = 0;

	int op = 0;
	char *arg_K = NULL;
	char *arg_j = NULL;
	char *arg_k = NULL;
	char *arg_l = NULL;
	char *arg_h = NULL;
	char *arg_S = NULL;
	char *arg_M = NULL;
	char *arg_m = NULL;

	uint8_t *raw_K = NULL;
	size_t raw_K_len = 0;

	uint32_t num_j = 0;

	uint8_t *raw_k = NULL;
	size_t raw_k_len = 0;

	uint32_t num_l = NULL;
	uint32_t num_h = 0;

	uint8_t *raw_S = NULL;

	uint8_t *raw_m = NULL;
	size_t raw_m_len = 0;

	char *out_m = NULL;
	size_t out_m_len = 0;

	opterr = 1;
	while ((rc = getopt(argc, argv, "DdeK:j:k:l:h:S:M:m:v")) != -1) {
		switch (rc) {

		case 'D': /* decrypt (plain) */
		case 'd': /* decrypt (base64) */
		case 'e': /* encrypt (base64) */
			op = rc;
			break;

		case 'K': /* key: base64 (hohha format) */
			arg_K = optarg;
			break;

		case 'j': /* override key jumps: numeric */
			arg_j = optarg;
			break;
		case 'k': /* override key body: base64 */
			arg_k = optarg;
			break;
		case 'l': /* override key length: numeric */
			arg_l = optarg;
			break;
		case 'h': /* override key checksum: numeric */
			arg_h = optarg;
			break;

		case 'S': /* override salt: eight numeric */
			arg_S = optarg;
			break;

		case 'M': /* message: plain */
			arg_M = optarg;
			arg_m = NULL;
			break;

		case 'm': /* message: base64 */
			arg_m = optarg;
			arg_M = NULL;
			break;

		case 'v': /* increase verbosity */
			++hohha_dbg_level;
			break;

		case ':':
		case '?':
			++errflg;
		}
	}

	if (!op) {
		fprintf(stderr, "missing one of -c or -d or -e\n");
		++errflg;
	}

	if (!arg_K) {
		if (!arg_j) {
			fprintf(stderr, "missing -K or -j for jumps\n");
			++errflg;
		}
		if (!arg_k) {
			fprintf(stderr, "missing -K or -k for key body\n");
			++errflg;
		}
		if (!arg_S) {
			fprintf(stderr, "missing -K or -S for salt\n");
			++errflg;
		}
	}

	if (!arg_M && !arg_m) {
		fprintf(stderr, "missing -M or -m for message\n");
		++errflg;
	}

	if (optind != argc) {
		fprintf(stderr, "error: trailing arguments... %s\n", argv[optind]);
		++errflg;
	}

	if (errflg) {
		fprintf(stderr,
			"usage: %s <method> <key> <message> [-v]\n"
			"\n"
			"  method: from the following options\n"
			"    -D\n"
			"      Decrypt the cyphertext message (plain)\n"
			"    -d\n"
			"      Decrypt the cyphertext message (base64)\n"
			"    -e\n"
			"      Encrypt the plaintext message (base64)\n"
			"\n"
			"  key: from the following options\n"
			"    -K <key>\n"
			"      Hohha key format (base64)\n"
			"    -j <jumps>\n"
			"      Override key jumps (numeric)\n"
			"    -k <body>\n"
			"      Override key body (base64)\n"
			"    -l <length>\n"
			"      Override key length (numeric)\n"
			"    -h <check>\n"
			"      Override key checksum (numeric)\n"
			"    -S <salt>\n"
			"      Override key salt (eight numeric)\n"
			"\n"
			"  message: from the following options\n"
			"    -M <msg>\n"
			"      Message (plain)\n"
			"    -m <msg>\n"
			"      Message (base64)\n"
			"\n"
			"  -v\n"
			"      Increase debug verbosity (may be repeated)\n"
			"\n",
			argv[0]);
		exit(2);
	}

	if (hohha_dbg_level > 0) {
		int v;

		fprintf(stderr, "command: %s -%c", argv[0], op);

		for (v = 0; v < hohha_dbg_level; ++v)
			fprintf(stderr, " -v");

		if (arg_K)
			fprintf(stderr, " -K '%s'", arg_K);

		if (arg_j)
			fprintf(stderr, " -j '%s'", arg_j);

		if (arg_k)
			fprintf(stderr, " -k '%s'", arg_k);

		if (arg_l)
			fprintf(stderr, " -l '%s'", arg_l);

		if (arg_l)
			fprintf(stderr, " -h '%s'", arg_h);

		if (arg_S)
			fprintf(stderr, " -S '%s'", arg_S);

		if (arg_M)
			fprintf(stderr, " -M '%s'", arg_M);

		if (arg_m)
			fprintf(stderr, " -m '%s'", arg_m);

		fprintf(stderr, "\n");
	}

	if (arg_K) {
		size_t sz;

		rc = b64_decode(arg_K, strlen(arg_K), NULL, &sz);
		if (rc) {
			fprintf(stderr, "invalid -K '%s'\n", arg_K);
			exit(1);
		}

		raw_K = malloc(sz);
		raw_K_len = sz;

		b64_decode(arg_K, strlen(arg_K), raw_K, &raw_K_len);
	}

	if (arg_j) {
		unsigned long val;

		errno = 0;
		val = strtoul(arg_j, NULL, 0);
		if (errno || val > UINT32_MAX) {
			fprintf(stderr, "invalid -j '%s'\n", arg_j);
			exit(1);
		}

		num_j = (uint32_t)val;
	} else {
		num_j = get_key_jumps(raw_K);
	}

	if (arg_k) {
		size_t sz;

		rc = b64_decode(arg_k, strlen(arg_k), NULL, &sz);
		if (rc) {
			fprintf(stderr, "invalid -k '%s'\n", arg_k);
			exit(1);
		}

		raw_k = malloc(sz);
		raw_k_len = sz;

		b64_decode(arg_k, strlen(arg_k), raw_k, &raw_k_len);
	} else {
		raw_k = get_key_body(raw_K);
		raw_k_len = raw_K_len - (raw_k - raw_K);
	}

	if (arg_l) {
		unsigned long val;

		errno = 0;
		val = strtoul(arg_l, NULL, 0);
		if (errno || val > UINT32_MAX) {
			fprintf(stderr, "invalid -l '%s'\n", arg_l);
			exit(1);
		}

		num_l = (uint32_t)val;
	} else if (arg_k) {
		num_l = raw_k_len;
	} else {
		num_l = get_key_len(raw_K);
	}

	if (arg_h) {
		unsigned long val;

		errno = 0;
		val = strtoul(arg_h, NULL, 0);
		if (errno || val > UINT32_MAX) {
			fprintf(stderr, "invalid -l '%s'\n", arg_h);
			exit(1);
		}

		num_h = (uint32_t)val;
	}

	if (arg_S) {
		raw_S = malloc(8);

		rc = sscanf(arg_S, "%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu\n",
		       &raw_S[0], &raw_S[1], &raw_S[2], &raw_S[3],
		       &raw_S[4], &raw_S[5], &raw_S[6], &raw_S[7]);
		if (rc != 8) {
			fprintf(stderr, "invalid -S '%s'\n", arg_S);
			exit(1);
		}
	} else {
		raw_S = get_key_salt(raw_K);
	}

	if (arg_M) {
		raw_m = (void *)arg_M;
		raw_m_len = strlen(arg_M);
	}

	if (arg_m) {
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

	if (num_l < raw_k_len) {
		fprintf(stderr, "warning: key length less than key data\n");
		fprintf(stderr, "    key length: %u\n", num_l);
		fprintf(stderr, "    key data: %zu\n", raw_k_len);
		fprintf(stderr, "    ignore trailing key data\n");
	} else if (num_l > raw_k_len) {
		fprintf(stderr, "warning: key length greater than key data\n");
		fprintf(stderr, "    key length: %u\n", num_l);
		fprintf(stderr, "    key data: %zu\n", raw_k_len);

		num_l = raw_k_len;
		fprintf(stderr, "    change key length to: %u\n", num_l);
	}

	hx = malloc(sizeof(*hx) + num_l);

	hx_init(hx, raw_k, num_l, num_j,
		*(uint32_t *)(raw_S),
		*(uint32_t *)(raw_S + 4),
		0);

	if (arg_h)
		hx->v = num_h;

	if (op == 'e')
		hx_encrypt(hx, raw_m, raw_m, raw_m_len);
	else
		hx_decrypt(hx, raw_m, raw_m, raw_m_len);

	if (op == 'D') {
		out_m = (void *)raw_m;
		out_m_len = raw_m_len;
	} else {
		out_m_len = (raw_m_len * 4 / 3 + 3) & ~3;
		out_m = malloc(out_m_len + 1);
		rc = b64_encode(raw_m, raw_m_len,
				out_m, out_m_len + 1);
		if (rc || strlen(out_m) != out_m_len) {
			fprintf(stderr, "bug: out_m_len inexact\n");
			exit(1);
		}
	}

	fwrite(out_m, 1, out_m_len, stdout);

	if (op != 'D' || isatty(1))
		fputc('\n', stdout);

	return 0;
}
