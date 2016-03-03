#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hohha_util.h"

int main(int argc, char **argv)
{
	int rc, errflg = 0;

	char *arg_M = NULL;
	char *arg_m = NULL;

	uint8_t *raw_m = NULL;
	size_t raw_m_len = 0;
	size_t raw_m_off = 0;

	uint32_t crc;

	opterr = 1;
	while ((rc = getopt(argc, argv, "M:m:K:k:v")) != -1) {
		switch (rc) {
		case 'M': /* message: plain */
			arg_M = optarg;
			arg_m = NULL;
			raw_m_off = 0;
			break;

		case 'K': /* key: base64 (hohha format) */
			arg_m = optarg;
			arg_M = NULL;
			raw_m_off = 11;
			break;

		case 'm': /* message: base64 */
		case 'k': /* key body: base64 */
			arg_m = optarg;
			arg_M = NULL;
			raw_m_off = 0;
			break;

		case 'v': /* increase verbosity */
			++hohha_dbg_level;
			break;

		case ':':
		case '?':
			++errflg;
		}
	}

	if (!arg_M && !arg_m) {
		fprintf(stderr, "missing one of the required options\n");
		++errflg;
	}

	if (optind != argc) {
		fprintf(stderr, "error: trailing arguments... %s\n", argv[optind]);
		++errflg;
	}

	if (errflg) {
		fprintf(stderr,
			"usage: %s <message> [-v]\n"
			"\n"
			"  message: from the following options\n"
			"    -M <msg>\n"
			"      Message (plain)\n"
			"    -m <msg>\n"
			"      Message (base64)\n"
			"    -K <key>\n"
			"      Hohha key format (base64)\n"
			"    -k <body>\n"
			"      Key body (base64)\n"
			"\n"
			"  -v\n"
			"      Increase debug verbosity (may be repeated)\n"
			"\n",
			argv[0]);
		exit(2);
	}

	if (arg_M) {
		raw_m = (void *)arg_M;
		raw_m_len = strlen(arg_M);
	}

	if (arg_m) {
		rc = b64_decode(arg_m, strlen(arg_m), NULL, &raw_m_len);
		if (rc) {
			fprintf(stderr, "invalid -m '%s'\n", arg_m);
			exit(1);
		}

		raw_m = malloc(raw_m_len);

		b64_decode(arg_m, strlen(arg_m), raw_m, &raw_m_len);
	}

	crc = crc32_data(raw_m + raw_m_off, raw_m_len - raw_m_off);

	printf("%#x (%u)\n", crc, crc);

	return 0;
}
