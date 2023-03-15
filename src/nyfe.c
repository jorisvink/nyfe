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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "nyfe.h"

static void	sighdlr(int);
static void	cmd_init(int, char **);
static void	cmd_keygen(int, char **);
static void	cmd_encrypt(int, char **);
static void	cmd_decrypt(int, char **);

static void	usage(void) __attribute__((noreturn));
static void	usage_keygen(void) __attribute__((noreturn));
static void	usage_encdec(void) __attribute__((noreturn));

static void	setup_paths(void);
static void	setup_signals(void);

static const char	*path_default_keyfile(void);

/* Busy spinner */
static const u_int8_t spinner[] = { '|', '/', '-', '\\', '|', '/', '-', '\\' };

/*
 * A list of supported commands and their callbacks.
 */
static const struct {
	const char	*cmd;
	void		(*cb)(int, char **);
} cmdtab[] = {
	{ "init",	cmd_init },
	{ "encrypt",	cmd_encrypt },
	{ "decrypt",	cmd_decrypt },
	{ "keygen",	cmd_keygen },
	{ NULL, NULL },
};

/* Last received signal, set via sighdlr(). */
static volatile sig_atomic_t	sig_recv = -1;

/* If we're showing messages on stdout. */
static int			nyfe_quiet = 0;

/* The default $HOME/.nyfe path. */
static char			homedir[PATH_MAX];

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

	nyfe_file_init();
	nyfe_random_init();
	nyfe_zeroize_init();

	setup_paths();
	setup_signals();

	cb(argc, argv);

	nyfe_zeroize_all();
	nyfe_file_remove_lingering();

	return (0);
}

/* Returns the last received signal. */
int
nyfe_signal_pending(void)
{
	return (sig_recv);
}

/* Log something to stdout unless we're quiet. */
void
nyfe_output(const char *fmt, ...)
{
	va_list		args;

	PRECOND(fmt != NULL);

	if (nyfe_quiet == 1)
		return;

	va_start(args, fmt);
	vprintf(fmt, args);
	va_end(args);

	fflush(stdout);
}

/* Move spinner to next state. */
void
nyfe_output_spin(void)
{
	static int	state = 0;

	if (nyfe_quiet == 0) {
		printf("\b%c", spinner[state++]);
		fflush(stdout);
		state = state % 7;
	}
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
	nyfe_file_remove_lingering();

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

/*
 * Resolve the user $HOME and fixup the default path to ~/.nyfe.
 * Will always mkdir() on this directory.
 */
static void
setup_paths(void)
{
	int			len;
	struct passwd		*pw;

	if ((pw = getpwuid(getuid())) == NULL)
		fatal("who are you? (%s)", errno_s);

	len = snprintf(homedir, sizeof(homedir), "%s/.nyfe", pw->pw_dir);
	if (len == -1 || (size_t)len >= sizeof(homedir))
		fatal("failed to construct path to homedir");

	if (mkdir(homedir, 0700) == -1 && errno != EEXIST)
		fatal("failed to create '%s': %s", homedir, errno_s);
}

/* Nyfe usage callback. */
static void
usage(void)
{
	fprintf(stderr, "Usage: nyfe [cmd] [cmdopts]\n");
	fprintf(stderr, "commands:\n");
	fprintf(stderr, "\tencrypt  - Encrypts a file\n");
	fprintf(stderr, "\tdecrypt  - Decrypts a file\n");
	fprintf(stderr, "\tkeygen   - Generate a new key file\n");
	fprintf(stderr, "\tinit     - Set up nyfe for the first time.\n");

	exit(1);
}

/* Nyfe encrypt | decrypt usage callback. */
static void
usage_encdec(void)
{
	fprintf(stderr, "Usage: nyfe encrypt/decrypt [options] [in] [out]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "\t-f  - Specifies which keyfile to use.\n");
	fprintf(stderr, "\t-q  - Be quiet.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "If -f was not specified nyfe will use ");
	fprintf(stderr, "$HOME/.nyfe/secret.key\n");

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

static void
usage_init(void)
{
	fprintf(stderr, "Usage: nyfe init\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Creates a default keyfile if it does not exist yet.");

	exit(1);
}

static const char *
path_default_keyfile(void)
{
	int		len;
	static char	path[PATH_MAX];

	len = snprintf(path, sizeof(path), "%s/secret.key", homedir);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to construct path to default keyfile");

	return (path);
}

/*
 * Initializes nyfe by making sure the default keyfile exists.
 * If it does not exist it will generate it.
 */
static void
cmd_init(int argc, char **argv)
{
	const char	*keyfile;

	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	if (argc != 1)
		usage_init();

	keyfile = path_default_keyfile();
	nyfe_key_generate(keyfile);

	printf("nyfe initialized!\n");
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

	while ((ch = getopt(argc, argv, "f:q")) != -1) {
		switch (ch) {
		case 'f':
			keyfile = optarg;
			break;
		case 'q':
			nyfe_quiet = 1;
			break;
		default:
			usage_encdec();
		}
	}

	argc -= optind;
	argv += optind;

	if (keyfile == NULL)
		keyfile = path_default_keyfile();

	if (argc != 2)
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

	nyfe_key_generate(argv[1]);
}
