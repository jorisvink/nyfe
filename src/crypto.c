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
#include <stdlib.h>
#include <unistd.h>

#include "nyfe.h"

/*
 * Confidentiality protection is done using XChaCha20 with Kc and Iv
 * derived using the key derivation specified below.
 *
 * Integrity protection is achieved using KMAC256() with Ki derived
 * using the key derivation specified below.
 *
 * Key derivation:
 *
 *	Rs = Random seed (512-bit)
 *	Id = Key identity (128-bit)
 *	Ki = Key for integrity (256-bit)
 *	Iv = Iv for confidentiality (192-bit)
 * 	Kc = Key for confidentiality (256-bit)
 *	Len = The original file size (64-bit)
 *
 *	K = The base symmetrical secret.
 *	X = Rs || Id
 *
 *	Kc, Iv, Ki = KMAC256(K, X, "NYFE.KDF")[88]
 *
 * 	ct = XChaCha20(Kc, Iv, pt)
 *	mac = KMAC256(Ki, Rs || Id || Len || ct, "NYFE.INTEGRITY")[64]
 *
 *	file = Rs || Id || ct || mac
 */

#define DERIVE_LABEL		"NYFE.KDF"
#define INTEGRITY_LABEL		"NYFE.INTEGRITY"

#define BLOCK_SIZE		(1024 * 1024 * 4)

static void	encrypt_setup(const void *, size_t, const void *, size_t,
		    const void *, size_t, struct nyfe_xchacha20 *,
		    struct nyfe_kmac256 *);

/*
 * Initialize and setup the XChaCha20 and KMAC256 context using key
 * material from the previously generated OKM.
 *
 * The domain specified is for the KMAC256 instance.
 */
void
nyfe_crypto_init(struct nyfe_xchacha20 *cipher, struct nyfe_kmac256 *kmac,
    const void *okm, size_t okm_len, const char *domain)
{
	const u_int8_t		*kc, *ki, *iv, *key;

	PRECOND(cipher != NULL);
	PRECOND(kmac != NULL);
	PRECOND(okm != NULL);
	PRECOND(okm_len == NYFE_OKM_LEN);
	PRECOND(domain != NULL);

	key = okm;

	kc = &key[0];
	iv = &key[NYFE_CONFIDENTIALITY_KEY_LEN];
	ki = &key[NYFE_CONFIDENTIALITY_KEY_LEN + NYFE_CONFIDENTIALITY_IV_LEN];

	nyfe_xchacha20_setup(cipher, kc, NYFE_CONFIDENTIALITY_KEY_LEN,
	    iv, NYFE_CONFIDENTIALITY_IV_LEN);

	nyfe_kmac256_init(kmac, ki, NYFE_INTEGRITY_KEY_LEN,
	    domain, strlen(domain));
}

/*
 * Encrypts the `in` file into `out`.
 */
void
nyfe_crypto_encrypt(const char *in, const char *out, const char *keyfile)
{
	size_t				ret;
	struct nyfe_key			key;
	struct nyfe_kmac256		kmac;
	struct nyfe_xchacha20		cipher;
	u_int8_t			*block;
	int				src, dst;
	u_int64_t			filelen;
	u_int8_t			seed[NYFE_SEED_LEN], mac[NYFE_MAC_LEN];

	PRECOND(in != NULL);
	PRECOND(out != NULL);
	PRECOND(keyfile != NULL);

	/*
	 * Verify and decrypt the selected keyfile.
	 * This automatically registers key as sensitive data.
	 */
	nyfe_key_load(&key, keyfile);

	/* Allocate block for i/o operations, freed later. */
	if ((block = calloc(1, BLOCK_SIZE)) == NULL)
		fatal("failed to allocate encryption buffer");

	/* Open and create the required file on disk. */
	src = nyfe_file_open(in, NYFE_FILE_READ);
	dst = nyfe_file_open(out, NYFE_FILE_CREATE);
	filelen = nyfe_file_size(src);

	/* Generate seed and write it to the destination file. */
	nyfe_random_bytes(seed, sizeof(seed));
	nyfe_file_write(dst, seed, sizeof(seed));

	/* Derive key material and setup cipher and kmac contexts. */
	encrypt_setup(key.data, sizeof(key.data), seed, sizeof(seed),
	    key.id, sizeof(key.id), &cipher, &kmac);
	nyfe_zeroize(&key, sizeof(key));

	/* Add the original file length to the integrity protection. */
	filelen = htobe64(filelen);
	nyfe_kmac256_update(&kmac, &filelen, sizeof(filelen));

	/*
	 * Read data from the source file and for each read block
	 * encrypt it under XChaCha20 and update the KMAC.
	 */
	for (;;) {
		ret = nyfe_file_read(src, block, BLOCK_SIZE);
		if (ret == 0)
			break;

		nyfe_xchacha20_encrypt(&cipher, block, block, ret);
		nyfe_kmac256_update(&kmac, block, ret);

		nyfe_file_write(dst, block, ret);
	}

	/* No longer need block at this point. */
	nyfe_mem_zero(block, BLOCK_SIZE);
	free(block);

	/* Finalize integrity protection and write the mac to the file. */
	nyfe_kmac256_final(&kmac, mac, sizeof(mac));
	nyfe_file_write(dst, mac, sizeof(mac));

	/* We no longer need any of this in memory. */
	nyfe_mem_zero(&cipher, sizeof(cipher));
	nyfe_mem_zero(&kmac, sizeof(kmac));

	(void)close(src);

	if (close(dst) == -1)
		fatal("close failed on '%s': %s", out, errno_s);
}

/*
 * Decrypt the encrypted `in` file into `out`.
 * If the integrity protection fails, the out file is removed.
 */
void
nyfe_crypto_decrypt(const char *in, const char *out, const char *keyfile)
{
	u_int32_t		ret;
	struct nyfe_key		key;
	struct nyfe_kmac256	kmac;
	struct nyfe_xchacha20	cipher;
	u_int8_t		*block;
	size_t			toread;
	int			src, dst;
	u_int64_t		filelen, swapped;
	u_int8_t		seed[NYFE_SEED_LEN];
	u_int8_t		mac[NYFE_MAC_LEN], expected[NYFE_MAC_LEN];

	PRECOND(in != NULL);
	PRECOND(out != NULL);
	PRECOND(keyfile != NULL);

	/*
	 * Verify and decrypt the selected keyfile.
	 * This automatically registers key as sensitive data.
	 */
	nyfe_key_load(&key, keyfile);

	/* Allocate block for i/o operations, freed later. */
	if ((block = calloc(1, BLOCK_SIZE)) == NULL)
		fatal("failed to allocate decryption buffer");

	/*
	 * Register memory that will contain sensitive information.
	 * If something goes wrong and we fatal() these are explicitly
	 * wiped before the program exits.
	 */
	nyfe_zeroize_register(&kmac, sizeof(kmac));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	/* Open and create the required file on disk. */
	src = nyfe_file_open(in, NYFE_FILE_READ);
	dst = nyfe_file_open(out, NYFE_FILE_CREATE);
	filelen = nyfe_file_size(src);

	/* Validate that the on-disk file seems reasonable. */
	if (filelen <= sizeof(seed) + sizeof(mac))
		fatal("%s: doesn't seem like an encrypted file", in);

	/* Read the seed from the source file. */
	if (nyfe_file_read(src, seed, sizeof(seed)) != sizeof(seed))
		fatal("failed to read seed from %s", in);

	/* Derive key material and setup cipher and kmac contexts. */
	encrypt_setup(key.data, sizeof(key.data), seed, sizeof(seed),
	    key.id, sizeof(key.id), &cipher, &kmac);
	nyfe_zeroize(&key, sizeof(key));

	/*
	 * Add what should be the original file length to the
	 * integrity protection.
	 */
	filelen -= sizeof(seed) + sizeof(mac);
	swapped = htobe64(filelen);
	nyfe_kmac256_update(&kmac, &swapped, sizeof(swapped));

	/*
	 * Read data from the encrypted file, updating the kmac context
	 * and decrypting it as we go.
	 */
	while (filelen) {
		toread = MIN(filelen, BLOCK_SIZE);

		if ((ret = nyfe_file_read(src, block, toread)) != toread)
			fatal("read %zu/%zu bytes", ret, toread);

		nyfe_kmac256_update(&kmac, block, toread);
		nyfe_xchacha20_encrypt(&cipher, block, block, toread);
		nyfe_file_write(dst, block, toread);

		filelen -= toread;
	}

	/* No longer needed at this point. */
	nyfe_zeroize(&cipher, sizeof(cipher));
	nyfe_mem_zero(block, BLOCK_SIZE);
	free(block);

	/* Read mac from the file. */
	if (nyfe_file_read(src, mac, sizeof(mac)) != sizeof(mac))
		fatal("failed to read mac from %s", in);

	/*
	 * Finalize the integrity protection and compare the
	 * expected mac vs the one obtained from the file.
	 */
	nyfe_kmac256_final(&kmac, expected, sizeof(expected));
	nyfe_zeroize(&kmac, sizeof(kmac));

	if (nyfe_mem_cmp(mac, expected, sizeof(expected)) != 0) {
		if (unlink(out) == -1) {
			printf("WARNING: failed to remove '%s', do not use\n",
			    out);
		}
		fatal("integrity check on '%s' failed", in);
	}

	(void)close(src);

	if (close(dst) == -1)
		fatal("close failed on '%s': %s", out, errno_s);
}

/*
 * Perform KDF to generate OKM and setup the cipher and kmac contexts
 * used for confidentiality and integrity protection.
 *
 * Adds the seed and keyID to the kmac context when ready.
 */
static void
encrypt_setup(const void *key, size_t key_len, const void *seed,
    size_t seed_len, const void *id, size_t id_len,
    struct nyfe_xchacha20 *cipher, struct nyfe_kmac256 *kmac)
{
	struct nyfe_kmac256		kdf;
	u_int8_t			okm[NYFE_OKM_LEN];

	PRECOND(key != NULL);
	PRECOND(key_len == NYFE_CONFIDENTIALITY_KEY_LEN);
	PRECOND(seed != NULL);
	PRECOND(seed_len == NYFE_SEED_LEN);
	PRECOND(id != NULL);
	PRECOND(id_len == NYFE_KEY_ID_LEN);
	PRECOND(cipher != NULL);
	PRECOND(kmac != NULL);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	/* KDF as detailed at the top of this file. */
	nyfe_kmac256_init(&kdf, key, key_len,
	    DERIVE_LABEL, sizeof(DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kdf, seed, seed_len);
	nyfe_kmac256_update(&kdf, id, id_len);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	/* Setup all crypto contexts. */
	nyfe_crypto_init(cipher, kmac, okm, sizeof(okm), INTEGRITY_LABEL);

	/* We no longer need any key material in okm now. */
	nyfe_zeroize(okm, sizeof(okm));

	/* Add the seed and keyID to the integrity protection. */
	nyfe_kmac256_update(kmac, seed, seed_len);
	nyfe_kmac256_update(kmac, id, id_len);
}
