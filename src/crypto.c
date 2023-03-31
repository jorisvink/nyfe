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
#include <sys/queue.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>

#include "nyfe.h"

/*
 * Confidentiality and integrity protection is achieved using the Agelas
 * AE cipher with Kc derived using the key derivation specified below.
 *
 * Key derivation:
 *	Rs = Random seed (512-bit)
 *	Id = Key identity (128-bit)
 * 	Kc = Key for Agelas (512-bit)
 *	Len = The original file size (64-bit, big endian)
 *
 *	K = The base symmetrical secret.
 *	X = len(Rs) || Rs || len(Id) || Id
 *	Kc, Iv = KMAC256(K, X, "NYFE.KDF")[88]
 *
 * 	ct, tag = Agelas(Kc, pt, aad = Rs || Id || Len)
 *	file = Rs || Id || ct || tag
 */

#define DERIVE_LABEL		"NYFE.KDF"
#define BLOCK_SIZE		(1024 * 1024 * 4)

static u_int64_t	crypto_size(u_int64_t);
static const char	*crypto_size_unit(u_int64_t);

static void	crypto_setup(const void *, size_t, const void *, size_t,
		    const void *, size_t, struct nyfe_agelas *);

/*
 * Encrypts the `in` file into `out`.
 */
void
nyfe_crypto_encrypt(const char *in, const char *out, const char *keyfile)
{
	size_t				ret;
	struct nyfe_key			key;
	struct nyfe_agelas		cipher;
	u_int8_t			*block;
	u_int64_t			filelen;
	int				src, dst, sig;
	u_int8_t			seed[NYFE_SEED_LEN], tag[NYFE_TAG_LEN];

	/* in may be NULL to indicate stdin. */
	/* out may be NULL to indicate stdout. */
	PRECOND(keyfile != NULL);

	/*
	 * If stdout was requested, we set dst to STODUT_FILENO, otherwise
	 * we open the destination file as early as possible so we can exit
	 * without too much secrets in memory early.
	 */
	if (out == NULL) {
		dst = STDOUT_FILENO;
	} else {
		dst = nyfe_file_open(out, NYFE_FILE_CREATE);
	}

	/*
	 * Verify and decrypt the selected keyfile.
	 * This automatically registers key as sensitive data.
	 */
	nyfe_key_load(&key, keyfile);

	/* Allocate block for i/o operations, freed later. */
	if ((block = calloc(1, BLOCK_SIZE)) == NULL)
		fatal("failed to allocate encryption buffer");

	/* If stdin was requested, just set src to STDIN_FILENO. */
	if (in == NULL) {
		src = STDIN_FILENO;
	} else {
		src = nyfe_file_open(in, NYFE_FILE_READ);
	}

	/* Generate seed and write it to the destination file. */
	nyfe_random_bytes(seed, sizeof(seed));
	nyfe_file_write(dst, seed, sizeof(seed));

	/* Derive key material and setup cipher context. */
	crypto_setup(key.data, sizeof(key.data), seed, sizeof(seed),
	    key.id, sizeof(key.id), &cipher);
	nyfe_zeroize(&key, sizeof(key));

	/*
	 * Read data from the source file and for each read block
	 * encrypt it under Agelas.
	 */
	filelen = 0;
	for (;;) {
		if ((sig = nyfe_signal_pending()) != -1) {
			if (out != NULL)
				(void)unlink(out);
			fatal("clean abort due to received signal %d", sig);
		}

		if ((ret = nyfe_file_read(src, block, BLOCK_SIZE)) == 0)
			break;

		nyfe_agelas_encrypt(&cipher, block, block, ret);
		nyfe_file_write(dst, block, ret);

		filelen += ret;
		nyfe_output("\33[K\rworking ... %" PRIu64 " %s",
		    crypto_size(filelen), crypto_size_unit(filelen));
	}

	/* No longer need block at this point. */
	nyfe_mem_zero(block, BLOCK_SIZE);
	free(block);

	/* Add the original file length as additional authenticated data. */
	filelen = htobe64(filelen);
	nyfe_agelas_aad(&cipher, &filelen, sizeof(filelen));

	/* Finalize integrity protection and write the tag to the file. */
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));
	nyfe_file_write(dst, tag, sizeof(tag));

	/* We no longer need any of this in memory. */
	nyfe_mem_zero(&cipher, sizeof(cipher));

	(void)close(src);

	if (dst != STDOUT_FILENO)
		nyfe_file_close(dst);

	nyfe_output("\ndone\n");
}

/*
 * Decrypt the encrypted `in` file into `out`.
 * If the integrity protection fails, the out file is removed.
 */
void
nyfe_crypto_decrypt(const char *in, const char *out, const char *keyfile)
{
	u_int32_t		ret;
	int			sig;
	struct nyfe_key		key;
	struct nyfe_agelas	cipher;
	u_int8_t		*block;
	u_int64_t		filelen;
	int			src, dst;
	u_int8_t		seed[NYFE_SEED_LEN];
	u_int8_t		tag[NYFE_TAG_LEN], expected[NYFE_TAG_LEN];

	/* in may be NULL to indicate stdin. */
	PRECOND(out != NULL);
	PRECOND(keyfile != NULL);

	/* Open the destination early, so we exit early if we can't do it. */
	dst = nyfe_file_open(out, NYFE_FILE_CREATE);

	/*
	 * Verify and decrypt the selected keyfile.
	 * This automatically registers key as sensitive data.
	 */
	nyfe_key_load(&key, keyfile);

	/* Allocate block for i/o operations, freed later. */
	if ((block = calloc(1, BLOCK_SIZE)) == NULL)
		fatal("failed to allocate decryption buffer");

	/* If stdin was requested, just set src to STDIN_FILENO. */
	if (in == NULL) {
		src = STDIN_FILENO;
	} else {
		src = nyfe_file_open(in, NYFE_FILE_READ);
	}

	/*
	 * Register memory that will contain sensitive information.
	 * If something goes wrong and we fatal() these are explicitly
	 * wiped before the program exits.
	 */
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	/* Read the seed from the source file. */
	if (nyfe_file_read(src, seed, sizeof(seed)) != sizeof(seed))
		fatal("failed to read seed from %s", in);

	/* Derive key material and setup cipher context. */
	crypto_setup(key.data, sizeof(key.data), seed, sizeof(seed),
	    key.id, sizeof(key.id), &cipher);
	nyfe_zeroize(&key, sizeof(key));

	/*
	 * Read data from the encrypted input, decrypting it as we go.
	 *
	 * We hold back up to sizeof(tag) bytes of data as we are
	 * reading from the source until EOF.
	 *
	 * This means we need to make sure the tag remains as the last
	 * part and is not swallowed by accident.
	 */
	filelen = 0;
	for (;;) {
		if ((sig = nyfe_signal_pending()) != -1) {
			(void)unlink(out);
			fatal("clean abort due to received signal %d", sig);
		}

		if ((ret = nyfe_file_read(src, block, BLOCK_SIZE)) == 0)
			break;

		if (filelen > 0) {
			nyfe_agelas_decrypt(&cipher, tag, tag, sizeof(tag));
			nyfe_file_write(dst, tag, sizeof(tag));
			filelen += sizeof(tag);
		}

		if (ret < sizeof(tag))
			fatal("%s: too short of a read", __func__);

		ret -= sizeof(tag);
		memcpy(tag, &block[ret], sizeof(tag));

		if (ret > 0) {
			nyfe_agelas_decrypt(&cipher, block, block, ret);
			nyfe_file_write(dst, block, ret);
			filelen += ret;
		}

		nyfe_output("\33[K\rworking ... %" PRIu64 " %s",
		    crypto_size(filelen), crypto_size_unit(filelen));
	}

	/*
	 * Add what should be the original file length as
	 * additional authenticated data.
	 */
	filelen = htobe64(filelen);
	nyfe_agelas_aad(&cipher, &filelen, sizeof(filelen));

	/* No longer needed at this point. */
	nyfe_mem_zero(block, BLOCK_SIZE);
	free(block);

	/*
	 * Finalize the integrity protection and compare the
	 * expected tag vs the one obtained from the file.
	 */
	nyfe_agelas_authenticate(&cipher, expected, sizeof(expected));
	nyfe_zeroize(&cipher, sizeof(cipher));

	if (nyfe_mem_cmp(tag, expected, sizeof(expected)) != 0) {
		if (unlink(out) == -1) {
			printf("WARNING: failed to remove '%s', do not use\n",
			    out);
		}
		fatal("integrity check on '%s' failed", in);
	}

	(void)close(src);
	nyfe_file_close(dst);

	nyfe_output("\ndone\n");
}

/*
 * Perform KDF to generate OKM and setup the Agelas cipher context
 * used for confidentiality and integrity protection.
 *
 * Adds the seed and keyID as AAD after setup.
 */
static void
crypto_setup(const void *key, size_t key_len, const void *seed,
    size_t seed_len, const void *id, size_t id_len,
    struct nyfe_agelas *cipher)
{
	struct nyfe_kmac256		kdf;
	u_int8_t			len;
	u_int8_t			okm[NYFE_OKM_LEN];

	PRECOND(key != NULL);
	PRECOND(key_len == NYFE_KEY_LEN);
	PRECOND(seed != NULL);
	PRECOND(seed_len == NYFE_SEED_LEN);
	PRECOND(id != NULL);
	PRECOND(id_len == NYFE_KEY_ID_LEN);
	PRECOND(cipher != NULL);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_output("deriving unique keys for this file ... ");

	/* KDF as detailed at the top of this file. */
	nyfe_kmac256_init(&kdf, key, key_len,
	    DERIVE_LABEL, sizeof(DERIVE_LABEL) - 1);

	len = seed_len;
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, seed, seed_len);

	len = id_len;
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, id, id_len);

	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	/* Setup all crypto contexts. */
	nyfe_agelas_init(cipher, okm, sizeof(okm));

	/* We no longer need any key material now. */
	nyfe_zeroize(okm, sizeof(okm));

	/* Add the seed and keyID as additional authenticated data. */
	nyfe_agelas_aad(cipher, seed, seed_len);
	nyfe_agelas_aad(cipher, id, id_len);

	nyfe_output("done\n");
}

/*
 * Returns the file length in the current human readable unit size.
 */
static u_int64_t
crypto_size(u_int64_t length)
{
	if (length >= (1 << 20))
		return (length >> 20);

	if (length >= (1 << 10))
		return (length >> 10);

	return (length);
}

/*
 * Returns the unit to be printed for the current file length.
 */
static const char *
crypto_size_unit(u_int64_t length)
{
	if (length >= (1 << 20))
		return ("MB");

	if (length >= (1 << 10))
		return ("KB");

	return ("b");
}
