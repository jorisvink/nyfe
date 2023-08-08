/*
 * Copyright (c) 2023 Joris Vink <joris@coma.one>
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
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "nyfe.h"

#define MEMORY_FAULT	\
    "nyfe: segmentation error, all sensitive memory has been wiped\n"

static void	sighdlr(int);
static void	sigmemfault(int);

static void	cmd_init(int, char **);
static void	cmd_test(int, char **);
static void	cmd_about(int, char **);
static void	cmd_keygen(int, char **);
static void	cmd_encrypt(int, char **);
static void	cmd_decrypt(int, char **);
static void	cmd_keyclone(int, char **);
static void	cmd_prng_test(int, char **);

static void	usage(void) __attribute__((noreturn));
static void	usage_keygen(void) __attribute__((noreturn));
static void	usage_encdec(void) __attribute__((noreturn));
static void	usage_keyclone(void) __attribute__((noreturn));

static void	setup_env(void);
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
	{ "test",	cmd_test },
	{ "about",	cmd_about },
	{ "encrypt",	cmd_encrypt },
	{ "decrypt",	cmd_decrypt },
	{ "keygen",	cmd_keygen },
	{ "keyclone",	cmd_keyclone },
	{ "prng-test",	cmd_prng_test },
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

	setup_env();
	setup_paths();
	setup_signals();

	nyfe_selftest_kmac256();

	nyfe_file_init();
	nyfe_random_init();
	nyfe_zeroize_init();

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

/* Log something to stderr unless we're quiet. */
void
nyfe_output(const char *fmt, ...)
{
	va_list		args;

	PRECOND(fmt != NULL);

	if (nyfe_quiet == 1)
		return;

	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);

	fflush(stderr);
}

/* Move spinner to next state. */
void
nyfe_output_spin(void)
{
	static int	state = 0;

	if (nyfe_quiet == 0) {
		fprintf(stderr, "\b%c", spinner[state++]);
		fflush(stderr);
		state = state % 7;
	}
}

/*
 * Read a passphrase from the user without echoing it.
 */
void
nyfe_read_passphrase(void *buf, size_t len)
{
	size_t			off;
	u_int8_t		*ptr;
	int			fd, sig;
	struct termios		cur, old;

	PRECOND(buf != NULL);
	PRECOND(len > 0);

	/* Kill echo on the terminal. */
	if ((fd = open(_PATH_TTY, O_RDWR)) == -1)
		fatal("open(%s): %s", _PATH_TTY, errno_s);

	if (tcgetattr(fd, &old) == -1)
		fatal("tcgetattr: %s", errno_s);

	cur = old;
	cur.c_lflag &= ~(ECHO | ECHONL);

	if (tcsetattr(fd, TCSAFLUSH, &cur) == -1) {
		(void)tcsetattr(fd, TCSANOW, &old);
		fatal("tcsetattr: %s", errno_s);
	}

	/* Read the passphrase from the user. */
	nyfe_output("passphrase: ");

	off = 0;
	ptr = buf;

	while (off != (len - 1)) {
		if ((sig = nyfe_signal_pending()) != -1)
			fatal("aborted due to received signal %d", sig);

		if (read(fd, &ptr[off], 1) == -1) {
			if (errno == EINTR)
				continue;
			fatal("%s: read failed: %s", __func__, errno_s);
		}

		if (ptr[off] == '\n')
			break;

		off++;
	}

	ptr[off] = '\0';

	/* Restore terminal settings. */
	if (tcsetattr(fd, TCSANOW, &old) == -1)
		fatal("tcsetattr: %s", errno_s);

	nyfe_output("\n");
}

/*
 * Returns the path to the entropy file location.
 */
const char *
nyfe_entropy_path(void)
{
	int		len;
	static char	path[PATH_MAX];

	len = snprintf(path, sizeof(path), "%s/entropy", homedir);
	if (len == -1 || (size_t)len >= sizeof(path))
		fatal("failed to construct path to entropy file");

	return (path);
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

/* Signal handler for SIGSEGV. */
static void
sigmemfault(int sig)
{
	/* Both of functions call only signal-safe functions. */
	nyfe_zeroize_all();
	nyfe_file_remove_lingering();

	(void)write(STDOUT_FILENO, MEMORY_FAULT, sizeof(MEMORY_FAULT) - 1);
	exit(1);
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

	sa.sa_handler = sigmemfault;

	if (sigaction(SIGSEGV, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/*
 * Setup operational environment to our liking.
 */
static void
setup_env(void)
{
	struct rlimit		rlim;

#if !defined(__APPLE__)
	if (mlockall(MCL_CURRENT | MCL_FUTURE) == -1)
		fatal("mlock: %s", errno_s);
#endif

	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	if (setrlimit(RLIMIT_CORE, &rlim) == -1)
		fatal("setrlimit(RLIMIT_CORE): %s", errno_s);
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
	fprintf(stderr, "\tkeyclone - Clone a keyfile\n");
	fprintf(stderr, "\tkeygen   - Generate a new key file\n");
	fprintf(stderr, "\tabout    - Nyfe version information\n");
	fprintf(stderr, "\tinit     - Set up nyfe for the first time\n");
	fprintf(stderr, "\ttest     - Performance test (halt with SIGINT)\n");

	exit(1);
}

/* Nyfe encrypt | decrypt usage callback. */
static void
usage_encdec(void)
{
	fprintf(stderr, "Usage: nyfe encrypt/decrypt [options] [in] [out]\n");
	fprintf(stderr, "\n");
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
usage_keyclone(void)
{
	fprintf(stderr, "Usage: nyfe keyclone [in] [out]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Clones the encrypted key data from a keyfile\n");
	fprintf(stderr, "into a new keyfile with a different passphrase.\n");

	exit(1);
}

static void
usage_init(void)
{
	fprintf(stderr, "Usage: nyfe init\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Create a default keyfile if it does not exist yet.\n");

	exit(1);
}

/*
 * Returns the path to the default key file location.
 */
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
	nyfe_key_generate(keyfile, NULL);

	printf("nyfe initialized!\n");
}

/*
 * Run performance tests on Agelas.
 */
static void
cmd_test(int argc, char **argv)
{
	struct nyfe_agelas	cipher;
	size_t			total, speed;
	u_int8_t		key[64], *block;
	time_t			now, last, start;

	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	memset(key, 0, sizeof(key));
	nyfe_agelas_init(&cipher, key, sizeof(key));

	if ((block = calloc(1, 1024 * 1024)) == NULL)
		fatal("failed to allocate test buffer");

	last = 0;
	speed = 0;
	total = 0;

	time(&start);
	last = now = start;

	for (;;) {
		if (nyfe_signal_pending() != -1)
			break;

		nyfe_agelas_encrypt(&cipher, block, block, 1024 * 1024);
		total++;
		speed++;

		time(&now);
		if ((now - last) >= 1) {
			printf("%zu MB / sec\n", speed);
			last = now;
			speed = 0;
		}
	}

	free(block);
	nyfe_mem_zero(&cipher, sizeof(cipher));

	printf("encrypted %zu MB in %" PRIu64 " seconds\n", total,
	    (u_int64_t)(now - start));
}

/*
 * Dump out output from the PRNG.
 */
static void
cmd_prng_test(int argc, char **argv)
{
	u_int8_t	data[1024];

	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	for (;;) {
		nyfe_random_bytes(data, sizeof(data));
		if (write(STDOUT_FILENO, data, sizeof(data)) == -1)
			fatal("failed to write to stdout");
	}
}

/*
 * Print some about information about Nyfe.
 */
static void
cmd_about(int argc, char **argv)
{
	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	printf("%s, built on %s\n", nyfe_version, nyfe_build_date);
}

/*
 * Callback for both encryption and decryption.
 * Will check the arguments specified and call the correct function.
 */
static void
encrypt_decrypt(int argc, char **argv, int encrypt)
{
	int		ch;
	const char	*keyfile, *in, *out;

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

	in = NULL;
	out = NULL;

	if (encrypt) {
		switch (argc) {
		case 0:
			break;
		case 1:
			out = argv[0];
			break;
		case 2:
			in = argv[0];
			out = argv[1];
			break;
		default:
			usage_encdec();
			/* NOTREACHED */
		}
	} else {
		switch (argc) {
		case 1:
			out = argv[0];
			break;
		case 2:
			in = argv[0];
			out = argv[1];
			break;
		default:
			usage_encdec();
			/* NOTREACHED */
		}
	}

	if (encrypt)
		nyfe_crypto_encrypt(in, out, keyfile);
	else
		nyfe_crypto_decrypt(in, out, keyfile);
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

	nyfe_key_generate(argv[1], NULL);
}

static void
cmd_keyclone(int argc, char **argv)
{
	PRECOND(argc >= 0);
	PRECOND(argv != NULL);

	if (argc != 3)
		usage_keyclone();

	nyfe_key_clone(argv[1], argv[2]);
}
