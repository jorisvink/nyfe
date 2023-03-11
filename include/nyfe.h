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

#ifndef __H_NYFE_H
#define __H_NYFE_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Apple .. */
#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
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

/* KMAC256 defines. */
#define NYFE_KMAC256_MAC_LEN		32

/* Constants for certain primitives. */
#define NYFE_KEY_ID_LEN			16
#define NYFE_MAC_LEN			64
#define NYFE_SEED_LEN			64
#define NYFE_KEY_LEN			32
#define NYFE_INTEGRITY_KEY_LEN		NYFE_KEY_LEN
#define NYFE_CONFIDENTIALITY_IV_LEN	24
#define NYFE_CONFIDENTIALITY_KEY_LEN	NYFE_KEY_LEN
#define NYFE_OKM_LEN			(NYFE_CONFIDENTIALITY_KEY_LEN + \
    NYFE_CONFIDENTIALITY_IV_LEN + NYFE_INTEGRITY_KEY_LEN)

/*
 * Our xchacha20 context.
 */
struct nyfe_xchacha20 {
	u_int32_t	input[16];
};

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
 * A key loaded from a key slot in the keyfile.
 */
struct nyfe_key {
	u_int8_t		id[NYFE_KEY_ID_LEN];
	u_int8_t		data[NYFE_CONFIDENTIALITY_KEY_LEN];
	u_int8_t		mac[NYFE_MAC_LEN];
} __attribute__((packed));

/* src/nyfe.c */
void	fatal(const char *, ...) __attribute__((noreturn));

/* src/crypto.c */
void	nyfe_crypto_decrypt(const char *, const char *, const char *);
void	nyfe_crypto_encrypt(const char *, const char *, const char *);
void	nyfe_crypto_init(struct nyfe_xchacha20 *, struct nyfe_kmac256 *,
	    const void *, size_t, const char *);

/* src/file.c */
u_int64_t	nyfe_file_size(int);
int		nyfe_file_open(const char *, int);
size_t		nyfe_file_read(int, void *, size_t);
void		nyfe_file_write(int, const void *, size_t);

/* src/mem.c */
void	nyfe_zeroize_all(void);
void	nyfe_zeroize(void *, size_t);
void	nyfe_mem_zero(void *, size_t);
void	nyfe_zeroize_register(void *, size_t);
int	nyfe_mem_cmp(const void *, const void *, size_t);

/* src/xchacha20.c */
void	nyfe_xchacha20_encrypt(struct nyfe_xchacha20 *, const void *,
	    void *, size_t);
void	nyfe_xchacha20_setup(struct nyfe_xchacha20 *, const u_int8_t *,
	    size_t, const u_int8_t *, size_t);

/* src/keccak1600.c */
void	nyfe_keccak1600_init(struct nyfe_keccak1600 *, u_int8_t, size_t);
void	nyfe_keccak1600_squeeze(struct nyfe_keccak1600 *, void *, size_t);
size_t	nyfe_keccak1600_absorb(struct nyfe_keccak1600 *,
	    const void *, size_t);

/* src/keys.c */
void	nyfe_key_generate(const char *);
void	nyfe_key_load(struct nyfe_key *, const char *);

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
void	nyfe_selftest_xchacha20(void);

/* src/random.c */
void	nyfe_random_init(void);
void	nyfe_random_bytes(void *, size_t);

#endif
