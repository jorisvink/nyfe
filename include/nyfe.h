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

#ifndef __H_NYFE_H
#define __H_NYFE_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Apple .. */
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe32(x)		OSSwapHostToBigInt32(x)
#define htobe64(x)		OSSwapHostToBigInt64(x)
#endif

/* Some handy macros. */
#define errno_s			strerror(errno)

#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

#define VERIFY(x)							\
	do {								\
		if (!(x)) {						\
			fatal("verification failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* File operations. */
#define NYFE_FILE_READ			1
#define NYFE_FILE_CREATE		2

/* Keccak1600 defines. */
#define NYFE_KECCAK_1600_RATE		1600
#define NYFE_KECCAK_1600_MIN_BITS	256
#define NYFE_KECCAK_1600_MAX_RATE	\
    ((NYFE_KECCAK_1600_RATE - NYFE_KECCAK_1600_MIN_BITS) / 8)

/* Constants for certain primitives. */
#define NYFE_KEY_ID_LEN		16
#define NYFE_TAG_LEN		32
#define NYFE_SEED_LEN		64
#define NYFE_KEY_LEN		64
#define NYFE_OKM_LEN		NYFE_KEY_LEN

/*
 * Our keccak1600 context.
 */
struct nyfe_keccak1600 {
	u_int64_t	A[5][5];

	size_t		rate;
	u_int8_t	padding;
};

/*
 * Our SHA3 context, builds on the Keccak1600 context.
 */
struct nyfe_sha3 {
	struct nyfe_keccak1600		keccak;
	size_t				offset;
	size_t				digest_len;
	u_int8_t			buf[NYFE_KECCAK_1600_MAX_RATE];
};

/*
 * Our KMAC256 context, builds on the SHA3 context.
 */
struct nyfe_kmac256 {
	struct nyfe_sha3		sha3;
	int				isxof;
};

/*
 * A key loaded from a keyfile.
 */
struct nyfe_key {
	u_int8_t		id[NYFE_KEY_ID_LEN];
	u_int8_t		data[NYFE_KEY_LEN];
	u_int8_t		tag[NYFE_TAG_LEN];
} __attribute__((packed));

/*
 * The agelas stream cipher context.
 */
struct nyfe_agelas {
	struct nyfe_keccak1600	sponge;
	size_t			offset;
	u_int64_t		counter;
	u_int8_t		k2[136];
	u_int8_t		state[136];
};

/* src/agelas.c */
void	nyfe_agelas_aad(struct nyfe_agelas *, const void *, size_t);
void	nyfe_agelas_init(struct nyfe_agelas *, const void *, size_t);
void	nyfe_agelas_authenticate(struct nyfe_agelas *, u_int8_t *, size_t);
void	nyfe_agelas_encrypt(struct nyfe_agelas *, const void *, void *, size_t);
void	nyfe_agelas_decrypt(struct nyfe_agelas *, const void *, void *, size_t);

/* src/nyfe.c */
void	nyfe_output_spin(void);
int	nyfe_signal_pending(void);
void	nyfe_read_passphrase(void *, size_t);
void	fatal(const char *, ...) __attribute__((noreturn));
void	nyfe_output(const char *, ...) __attribute__((format (printf, 1, 2)));

const char	*nyfe_entropy_path(void);

/* src/crypto.c */
void	nyfe_crypto_decrypt(const char *, const char *, const char *);
void	nyfe_crypto_encrypt(const char *, const char *, const char *);

/* src/file.c */
u_int64_t	nyfe_file_size(int);
void		nyfe_file_init(void);
void		nyfe_file_close(int);
void		nyfe_file_remove_lingering(void);
int		nyfe_file_open(const char *, int);
size_t		nyfe_file_read(int, void *, size_t);
void		nyfe_file_write(int, const void *, size_t);

/* src/mem.c */
void	nyfe_zeroize_all(void);
void	nyfe_zeroize_init(void);
void	nyfe_zeroize(void *, size_t);
void	nyfe_mem_zero(void *, size_t);
void	nyfe_zeroize_register(void *, size_t);
int	nyfe_mem_cmp(const void *, const void *, size_t);

/* src/keccak1600.c */
void	nyfe_keccak1600_init(struct nyfe_keccak1600 *, u_int8_t, size_t);
void	nyfe_keccak1600_squeeze(struct nyfe_keccak1600 *, void *, size_t);
size_t	nyfe_keccak1600_absorb(struct nyfe_keccak1600 *,
	    const void *, size_t);

/* src/keys.c */
void	nyfe_key_clone(const char *, const char *);
void	nyfe_key_load(struct nyfe_key *, const char *);
void	nyfe_key_generate(const char *, struct nyfe_key *);

/* src/sha3.c */
void	nyfe_sha3_init256(struct nyfe_sha3 *);
void	nyfe_sha3_init512(struct nyfe_sha3 *);
void	nyfe_xof_shake128_init(struct nyfe_sha3 *);
void	nyfe_xof_shake256_init(struct nyfe_sha3 *);
void	nyfe_sha3_final(struct nyfe_sha3 *, u_int8_t *, size_t);
void	nyfe_sha3_update(struct nyfe_sha3 *, const void *, size_t);

/* src/kmac256.c */
void	nyfe_kmac256_xof(struct nyfe_kmac256 *);
void	nyfe_kmac256_final(struct nyfe_kmac256 *, u_int8_t *, size_t);
void	nyfe_kmac256_update(struct nyfe_kmac256 *, const void *, size_t);
void	nyfe_kmac256_init(struct nyfe_kmac256 *, const void *, size_t,
	    const void *, size_t);

/* src/selftests.c */
void	nyfe_selftest_kmac256(void);

/* src/random.c */
void	nyfe_random_init(void);
void	nyfe_random_bytes(void *, size_t);

/* version information. */
extern const char	*nyfe_version;
extern const char	*nyfe_build_date;

#endif
