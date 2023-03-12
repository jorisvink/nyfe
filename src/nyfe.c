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

#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nyfe.h"

static void	sighdlr(int);
static void	cmd_keygen(int, char **);
static void	cmd_encrypt(int, char **);
static void	cmd_decrypt(int, char **);

static void	usage(void) __attribute__((noreturn));
static void	usage_keygen(void) __attribute__((noreturn));
static void	usage_encdec(void) __attribute__((noreturn));

static void	setup_signals(void);

/*
 * A list of supported commands and their callbacks.
 */
static const struct {
	const char	*cmd;
	void		(*cb)(int, char **);
} cmdtab[] = {
	{ "encrypt",	cmd_encrypt },
	{ "decrypt",	cmd_decrypt },
	{ "keygen",	cmd_keygen },
	{ NULL, NULL },
};

/* Last received signal, set via sighdlr(). *(
static volatile sig_atomic_t	sig_recv = -1;

/*
 * Nyfe entry point, will check what commands were specified on the command
 * line, run some self tests, setup the random system, signals and finally
 * calls into the correct callback.
 */
int
main(int argc, char *argv[])
{
	int			i;
	void			(*cb)(int, char **);

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
	setup_signals();

	cb(argc, argv);

	nyfe_zeroize_all();

	return (0);
}

/* Returns the last received signal. */
int
nyfe_signal_pending(void)
{
	return (sig_recv);
}

/*
 * A fatal error occurred, we will need to clean up.
 *
 * Before we do, block *all* signals that are blockable so we do
 * not get interrupted in our cleanup as we need to wipe sensitive
 * information from memory.
 */
void
fatal(const char *fmt, ...)
{
	sigset_t	sig;
	va_list		args;

	if (sigfillset(&sig) == -1)
		printf("warning: sigfillset failed\n");

	(void)sigprocmask(SIG_BLOCK, &sig, NULL);

	nyfe_zeroize_all();

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fprintf(stderr, "\n");

	exit(1);
}

/* Signal handler callback, install belowed via sigaction(). */
static void
sighdlr(int sig)
{
	sig_recv = sig;
}

/* Setup all relevant signals to call sighldr(). */
static void
setup_signals(void)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset failed");

	if (sigaction(SIGQUIT, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
	if (sigaction(SIGHUP, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
	if (sigaction(SIGINT, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/* Nyfe usage callback. */
static void
usage(void)
{
	fprintf(stderr, "Usage: nyfe [cmd] [cmdopts]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "\tencrypt  - Encrypts a file or directory\n");
	fprintf(stderr, "\tdecrypt  - Decrypts an encrypted file\n");
	fprintf(stderr, "\tkeygen   - Generate a new key file\n");

	exit(1);
}

/* Nyfe encrypt | decrypt usage callback. */
static void
usage_encdec(void)
{
	fprintf(stderr, "Usage: nyfe encrypt/decrypt [options] [in] [out]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "\t-f  - Specifies which keyfile to use. (required)\n");

	exit(1);
}

/* Nyfe keygen usage callback. */
static void
usage_keygen(void)
{
	fprintf(stderr, "Usage: nyfe keygen [file]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "The file argument is where the key is written too.\n");

	exit(1);
}

/*
 * Callback for both encryption and decryption.
 * Will check the arguments specified and call the correct function.
 */
static void
encrypt_decrypt(int argc, char **argv, int encrypt)
{
	int		ch;
	const char	*keyfile;

	PRECOND(argc >= 0);
	PRECOND(argv != NULL);
	PRECOND(encrypt == 0 || encrypt == 1);

	keyfile = NULL;

	while ((ch = getopt(argc, argv, "f:")) != -1) {
		switch (ch) {
		case 'f':
			keyfile = optarg;
			break;
		default:
			usage_encdec();
		}
	}

	argc -= optind;
	argv += optind;

	if (keyfile == NULL || argc != 2)
		usage_encdec();

	if (encrypt)
		nyfe_crypto_encrypt(argv[0], argv[1], keyfile);
	else
		nyfe_crypto_decrypt(argv[0], argv[1], keyfile);
}

/* Entry points for the revelant commands. */
static void
cmd_encrypt(int argc, char **argv)
{
	encrypt_decrypt(argc, argv, 1);
}

static void
cmd_decrypt(int argc, char **argv)
{
	encrypt_decrypt(argc, argv, 0);
}

static void
cmd_keygen(int argc, char **argv)
{
	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	if (argc != 2)
		usage_keygen();

	printf("generating key into %s\n", argv[1]);
	nyfe_key_generate(argv[1]);
}
