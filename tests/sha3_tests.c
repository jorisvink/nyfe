/*
 * Copyright (c) 2023 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__)
#include <bsd/stdlib.h>
#endif

#include "libnyfe.h"

#define MONTE_COUNT		100
#define	INBUFLEN		(1024 * 1024)

void	fatal(const char *, ...) __attribute__((noreturn));
void	test_input(const char *, int, int);

void	input_hex2bin(char *, u_int8_t **, size_t *);
int	input_read_line(FILE *, const char *, char *, size_t);

int	input_get_monte(FILE *, u_int8_t **, size_t *, u_int8_t **, size_t);
int	input_get_message(FILE *, u_int8_t **, size_t *, u_int8_t **, size_t *);

int	test_monte(const char *, FILE *, struct nyfe_sha3 *, size_t);
int	test_message(const char *, FILE *, struct nyfe_sha3 *, size_t);

int
main(int argc, char *argv[])
{
	const char	*errstr;
	int		ch, capacity, monte;

	monte = 0;
	errstr = NULL;
	capacity = -1;

	while ((ch = getopt(argc, argv, "c:m")) != -1) {
		switch (ch) {
		case 'c':
			capacity = strtonum(optarg, 256, 512, &errstr);
			if (errstr != NULL)
				fatal("%s: %s", optarg, errstr);
			if (capacity != 256 && capacity != 512)
				fatal("capacity must be 256 or 512");
			break;
		case 'm':
			monte = 1;
			break;
		default:
			fatal("Usage: sha3_tests [-c capacity] [file]");
		}
	}

	argc -= optind;
	argv += optind;

	if (capacity == -1)
		fatal("no capacity (-c) specified");

	if (argc != 1)
		fatal("Usage: sha3_tests [-c capacity] [file]");

	test_input(argv[0], capacity, monte);

	return (0);
}

/*
 * Read input from the source file, and run the appropriate tests.
 */
void
test_input(const char *file, int capacity, int monte)
{
	FILE			*fp;
	struct nyfe_sha3	ctx;
	size_t			expected;

	if ((fp = fopen(file, "r")) == NULL)
		fatal("failed to open '%s': %s", file, strerror(errno));

	for (;;) {
		if (capacity == 256) {
			expected = 32;
			nyfe_sha3_init256(&ctx);
		} else if (capacity == 512) {
			expected = 64;
			nyfe_sha3_init512(&ctx);
		} else {
			fatal("unknown capacity: %d", capacity);
		}

		if (monte) {
			if (test_monte(file, fp, &ctx, expected) == -1)
				break;
		} else {
			if (test_message(file, fp, &ctx, expected) == -1)
				break;
		}
	}

	fclose(fp);
}

/*
 * Monte Carlo test, produces 100.000 hashes, with intermediate
 * checkpoints every 1000 hashes.
 *
 * We compare the checkpoints from the input file against
 * the calculated digests and error out if they mismatch.
 */
int
test_monte(const char *file, FILE *fp, struct nyfe_sha3 *ctx, size_t expected)
{
	u_int8_t		digest[64];
	size_t			seedlen, i, j;
	u_int8_t		*seed, *mds[MONTE_COUNT];

	if (input_get_monte(fp, &seed, &seedlen, mds, expected) == -1)
		return (-1);

	if (seedlen > sizeof(digest))
		fatal("nope");

	memcpy(digest, seed, seedlen);

	for (j = 0; j < MONTE_COUNT; j++) {
		for (i = 0; i < 1000; i++) {
			if (expected == 32)
				nyfe_sha3_init256(ctx);
			else if (expected == 64)
				nyfe_sha3_init512(ctx);
			else
				fatal("unknown digest");

			nyfe_sha3_update(ctx, digest, expected);
			nyfe_sha3_final(ctx, digest, expected);
		}

		if (memcmp(digest, mds[j], expected))
			fatal("%s - [COUNT %zu] test failed", file, j);

		printf("%s - [COUNT %zu] test OK\n", file, j);
	}

	free(seed);

	for (i = 0; i < MONTE_COUNT; i++)
		free(mds[i]);

	return (0);
}

/*
 * Test hashing a single message and compare it to the expected digest.
 * We fail if they mismatch.
 */
int
test_message(const char *file, FILE *fp, struct nyfe_sha3 *ctx, size_t expected)
{
	u_int8_t		*msg, *md;
	u_int8_t		digest[64];
	size_t			msglen, mdlen;

	if (input_get_message(fp, &msg, &msglen, &md, &mdlen) == -1)
		return (-1);

	if (mdlen != expected)
		fatal("bad md length (%zu != %zu)", mdlen, expected);

	if (msg != NULL && msglen > 0)
		nyfe_sha3_update(ctx, msg, msglen);

	nyfe_sha3_final(ctx, digest, expected);

	if (memcmp(digest, md, mdlen))
		fatal("%s - [%zu] test failed", file, msglen * 8);

	printf("%s - [%zu] test OK\n", file, msglen * 8);

	free(msg);
	free(md);

	return (0);
}

/*
 * Read from the input file a single message to be tested.
 *
 * Expects the format to be:
 * 	Len = XXX
 *	Msg = ABCDEF1234567890
 *	MD = ABCDEF1234567890
 */
int
input_get_message(FILE *fp, u_int8_t **msg, size_t *msglen,
    u_int8_t **md, size_t *mdlen)
{
	char		*buf;
	size_t		length;
	const char	*errstr;

	*msg = NULL;
	*msglen = 0;

	if ((buf = malloc(INBUFLEN)) == NULL)
		fatal("malloc failed");

	if (input_read_line(fp, "Len = ", buf, INBUFLEN) == -1) {
		free(buf);
		return (-1);
	}

	length = strtonum(buf, 0, UINT_MAX, &errstr);
	if (errstr != NULL)
		fatal("invalid length: %s", buf);

	length = length / 8;

	if (input_read_line(fp, "Msg = ", buf, INBUFLEN) == -1) {
		free(buf);
		return (-1);
	}

	if (length > 0) {
		input_hex2bin(buf, msg, msglen);
		if (length != *msglen)
			fatal("message length is incorrect");
	}

	if (input_read_line(fp, "MD = ", buf, INBUFLEN) == -1) {
		free(buf);
		return (-1);
	}

	input_hex2bin(buf, md, mdlen);

	free(buf);

	return (0);
}

/*
 * Read from the source file the entire Monte Carlo test and
 * all 100 checkpoints.
 */
int
input_get_monte(FILE *fp, u_int8_t **seed, size_t *seedlen,
    u_int8_t **mds, size_t expected)
{
	char		*buf;
	size_t		idx, digestlen;

	if ((buf = malloc(INBUFLEN)) == NULL)
		fatal("malloc failed");

	if (input_read_line(fp, "Seed = ", buf, INBUFLEN) == -1) {
		free(buf);
		return (-1);
	}

	input_hex2bin(buf, seed, seedlen);

	for (idx = 0; idx < MONTE_COUNT; idx++) {
		if (input_read_line(fp, "COUNT = ", buf, INBUFLEN) == -1) {
			free(buf);
			return (-1);
		}

		if (input_read_line(fp, "MD = ", buf, INBUFLEN) == -1) {
			free(buf);
			return (-1);
		}

		input_hex2bin(buf, &mds[idx], &digestlen);

		if (digestlen != expected)
			fatal("digest %zu != %zu", digestlen, expected);
	}

	free(buf);

	return (0);
}

/*
 * Helper to convert a hex string into bytes.
 */
void
input_hex2bin(char *hex, u_int8_t **out, size_t *outlen)
{
	u_int8_t	*buf;
	char		hb[5];
	size_t		len, idx, j, buflen;

	if (strlen(hex) & 1)
		fatal("length of hex string not multiple of two");

	len = strlen(hex);
	buflen = len / 2;

	if ((buf = malloc(buflen)) == NULL)
		fatal("malloc failed");

	j = 0;

	hb[0] = '0';
	hb[1] = 'x';
	hb[4] = '\0';

	for (idx = 0; idx < len; idx += 2) {
		hb[2] = hex[idx];
		hb[3] = hex[idx + 1];
		buf[j++] = strtoul(hb, NULL, 16);
	}

	*out = buf;
	*outlen = buflen;
}

/*
 * Helper to read a line from an input file (ignoring comments and
 * empty lines completely).
 */
int
input_read_line(FILE *fp, const char *prefix, char *in, size_t len)
{
	char		*p;
	size_t		prefix_len;

	prefix_len = strlen(prefix);

	for (;;) {
		if (fgets(in, len, fp) == NULL)
			return (-1);

		p = in;
		in[strcspn(in, "\r\n")] = '\0';

		if (p[0] == '#' || p[0] == '\0' || p[0] == '[')
			continue;

		if (strncmp(prefix, in, prefix_len))
			fatal("expected '%s', got '%s'", prefix, in);

		memmove(in, in + prefix_len, strlen(in) - prefix_len);
		in[strlen(in) - prefix_len] = '\0';

		break;
	}

	return (0);
}

/*
 * Terrible, terrible things happened.
 */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}
