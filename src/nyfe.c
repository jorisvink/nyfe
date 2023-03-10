/*
 * Copyright (c) 2023 Joris Vink <joris@coders.se>
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
#include <sys/queue.h>

#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nyfe.h"

static void	cmd_encrypt(int, char **);
static void	cmd_decrypt(int, char **);

static void	usage(void) __attribute__((noreturn));
static void	usage_encrypt(void) __attribute__((noreturn));

static const struct {
	const char	*cmd;
	void		(*cb)(int, char **);
} cmdtab[] = {
	{ "encrypt",	cmd_encrypt },
	{ "decrypt",	cmd_decrypt },
	{ NULL, NULL },
};

int
main(int argc, char *argv[])
{
	int		i;
	void		(*cb)(int, char **);

	if (argc < 2)
		usage();

	cb = NULL;

	for (i = 0; cmdtab[i].cmd != NULL; i++) {
		if (!strcmp(cmdtab[i].cmd, argv[1])) {
			cb = cmdtab[i].cb;
			break;
		}
	}

	if (cb == NULL)
		usage();

	argc--;
	argv++;

	nyfe_selftest_kmac256();
	nyfe_selftest_xchacha20();

	nyfe_random_init();

	cb(argc, argv);

	nyfe_zeroize_all();

	return (0);
}

void
fatal(const char *fmt, ...)
{
	sigset_t	sig;
	va_list		args;

	sigfillset(&sig);
	(void)sigprocmask(SIG_BLOCK, &sig, NULL);

	nyfe_zeroize_all();

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: nyfe [cmd] [cmdopts]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "\tencrypt  - Encrypts a file or directory\n");
	fprintf(stderr, "\tdecrypt  - Decrypts an encrypted file\n");

	exit(1);
}

static void
usage_encrypt(void)
{
	fprintf(stderr, "Usage: nyfe encrypt [options] [in] [out]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "\t-k  - Specifies the symmetrical key ID to use.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "The in argument is either a file or directory.\n");
	fprintf(stderr, "The out argument is the file that is created.\n");

	exit(1);
}

static void
cmd_encrypt(int argc, char **argv)
{
	int		ch;
	const char	*keyid;

	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	keyid = NULL;

	while ((ch = getopt(argc, argv, "k:")) != -1) {
		switch (ch) {
		case 'k':
			keyid = optarg;
			break;
		default:
			usage_encrypt();
		}
	}

	argc -= optind;
	argv += optind;

	if (keyid == NULL || argc != 2)
		usage_encrypt();

	nyfe_encrypt(argv[0], argv[1]);
}

static void
cmd_decrypt(int argc, char **argv)
{
	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	if (argc != 3)
		usage_encrypt();

	nyfe_decrypt(argv[1], argv[2]);
}
