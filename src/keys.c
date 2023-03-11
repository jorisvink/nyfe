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

#if defined(__linux__)
#include <bsd/readpassphrase.h>
#else
#include <readpassphrase.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nyfe.h"

/*
 * Nyfe can use different key files. Each key file stores a single
 * symmetrical secret, together with its unique ID and key data.
 *
 * Definitions:
 *
 *	Id = 128-bit key identifier
 *	Kb = 256-bit symmetrical key
 *	passphrase = User supplied passphrase
 *
 *	Ki = Key for integrity (256-bit)
 *	Iv = Iv for confidentiality (192-bit)
 *	Kc = Key for confidentiality (256-bit)
 * 	Rs = Random seed from keyfile (512-bit)
 *
 * To verify and decrypt a keyfile:
 *
 *	K = passphrase_kdf(passphrase, Rs[0..32])[32]
 *	Kc, Iv, Ki = KMAC256(K, seed, "NYFE.KEYFILE.KDF")
 *	ct = XChaCha20(Kc, Iv, Id || Kb)
 *	mac = KMAC256(Ki, Ks || ct, "NYFE.KEYFILE.INTEGRITY")[64]
 *
 * The passphrase_kdf(passphrase, salt) function:
 *
 *	tmp = Intermediate buffer holding pseudorandom data
 *	ap = Pseudorandom generated list of accesses into tmp
 *	buf = SHAKE256(len(passphrase) || passphrase || salt)[512]
 *	Kt = 256-bit xchacha20 key to generate key stream (buf_0[0..32])
 *	Iv = 192-bit xchacha20 nonce to generate key stream (buf_0[32..56])
 *	Km = 256-bit KMAC256 key (tmp[0..32])
 *
 *	ap = SHAKE256(buf[0..256])[PASSPHRASE_KDF_AP_SIZE]
 *	tmp = SHAKE256(buf[256..512])[PASSPHRASE_KDF_MEM_SIZE]
 *	tmp = XChaCha20(Kt, Iv, tmp)
 *
 *	for iter = 0, iter < PASSPHRASE_KDF_ITERATIONS; do
 *		offset = ap[iter] * PASSPHRASE_KDF_STEP_LEN
 *		tmp[offset..offset+256] ^= SHAKE256(tmp[0..256])
 *
 *	X = tmp[32..PASSPHRASE_KDF_MEM_SIZE]
 *	return KMAC256(Km, X, "NYFE.PASSPHRASE.KDF")[32]
 */

/* Passphrase KDF settings, will use 32MB memory, 65536 iterations. */
#define PASSPHRASE_KDF_ITERATIONS	65536
#define PASSPHRASE_KDF_MEM_SIZE		(1024 * 1024 * 32)
#define PASSPHRASE_KDF_STEP_LEN		\
    (PASSPHRASE_KDF_MEM_SIZE / PASSPHRASE_KDF_ITERATIONS)
#define PASSPHRASE_KDF_AP_SIZE		\
    (PASSPHRASE_KDF_ITERATIONS * sizeof(u_int16_t))
#define PASSPHRASE_DERIVE_LABEL		"NYFE.PASSPHRASE.KDF"

/* KMAC256 customization strings for KDF and integrity protection. */
#define KDF_DERIVE_LABEL		"NYFE.KEYFILE.KDF"
#define KDF_INTEGRITY_LABEL		"NYFE.KEYFILE.INTEGRITY"

/*
 * Half of the seed is used as a salt into key_passphrase_kdf() while
 * half of it is used as seed for key_kdf().
 */
#define KEY_FILE_SALT_LEN		(NYFE_SEED_LEN / 2)

static void	key_generate_secret(struct nyfe_xchacha20 *,
		    struct nyfe_kmac256 *, const u_int8_t *, size_t);
static void	key_passphrase_kdf(const void *, u_int32_t, const void *,
		    size_t, u_int8_t *, size_t);

/*
 * Attempt to verify and decrypt a Nyfe key in the given file.
 * If successfull the key is returned via the `key` argument.
 */
void
nyfe_key_load(struct nyfe_key *key, const char *file)
{
	int				fd;
	struct nyfe_kmac256		kmac;
	struct nyfe_xchacha20		cipher;
	u_int8_t			mac[NYFE_MAC_LEN];
	u_int8_t			seed[NYFE_SEED_LEN];

	PRECOND(key != NULL);
	PRECOND(file != NULL);

	/* Open the suspected keyfile, read in the seed and key. */
	fd = nyfe_file_open(file, NYFE_FILE_READ);
	if (nyfe_file_read(fd, seed, sizeof(seed)) != sizeof(seed))
		fatal("failed to read seed from %s", file);
	if (nyfe_file_read(fd, key, sizeof(*key)) != sizeof(*key))
		fatal("failed to read key data from %s", file);

	/* Register any sensitive buffers. */
	nyfe_zeroize_register(key, sizeof(*key));
	nyfe_zeroize_register(&kmac, sizeof(kmac));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	/* Generate the key material and verify the integrity of the keyfile. */
	key_generate_secret(&cipher, &kmac, seed, sizeof(seed));
	nyfe_kmac256_update(&kmac, key->id, sizeof(key->id));
	nyfe_kmac256_update(&kmac, key->data, sizeof(key->data));
	nyfe_kmac256_final(&kmac, mac, sizeof(mac));

	if (nyfe_mem_cmp(mac, key->mac, sizeof(mac)) != 0)
		fatal("integrity check on '%s' failed", file);

	/* Integrity lg2m, decrypt the actual key data. */
	nyfe_xchacha20_encrypt(&cipher,
	    key->data, key->data, sizeof(key->data));

	/* Don't call nyfe_zeroize() on key as the caller will use it. */
	nyfe_zeroize(&kmac, sizeof(kmac));
	nyfe_zeroize(&cipher, sizeof(cipher));

	(void)close(fd);
}

/*
 * Generate a new key into the given keyfile.
 */
void
nyfe_key_generate(const char *file)
{
	int				fd;
	struct nyfe_key			key;
	struct nyfe_kmac256		kmac;
	struct nyfe_xchacha20		cipher;
	u_int8_t			mac[NYFE_MAC_LEN];
	u_int8_t			seed[NYFE_SEED_LEN];

	PRECOND(file != NULL);

	/*
	 * Generate the key ID and the key data, do a nyfe_random_init()
	 * in between so both outputs are not related to each other since
	 * id is stored in plaintext in the key file.
	 */
	nyfe_random_bytes(key.id, sizeof(key.id));
	nyfe_random_init();
	nyfe_random_bytes(key.data, sizeof(key.data));
	nyfe_random_init();

	/* Generate random seed and derive key material for this file. */
	nyfe_random_bytes(seed, sizeof(seed));
	key_generate_secret(&cipher, &kmac, seed, sizeof(seed));

	/* Encrypt the key data. */
	nyfe_xchacha20_encrypt(&cipher, key.data, key.data, sizeof(key.data));

	/* Generate the mac over all relevant data. */
	nyfe_kmac256_update(&kmac, key.id, sizeof(key.id));
	nyfe_kmac256_update(&kmac, key.data, sizeof(key.data));
	nyfe_kmac256_final(&kmac, mac, sizeof(mac));

	/* Open the file and write all contents. */
	fd = nyfe_file_open(file, NYFE_FILE_CREATE);

	nyfe_file_write(fd, seed, sizeof(seed));
	nyfe_file_write(fd, key.id, sizeof(key.id));
	nyfe_file_write(fd, key.data, sizeof(key.data));
	nyfe_file_write(fd, mac, sizeof(mac));

	nyfe_mem_zero(&key, sizeof(key));
	nyfe_mem_zero(&kmac, sizeof(kmac));
	nyfe_mem_zero(&cipher, sizeof(cipher));

	if (close(fd) == -1) {
		if (unlink(file) == -1) {
			printf("WARNING: failed to remove '%s', do not use\n",
			    file);
		}
		fatal("close failed on '%s': %s", file, errno_s);
	}
}

/*
 * Helper function to derive the required key material to setup the
 * XChaCha20 and KMAC256 contexts for confidentiality and integrity
 * protection on key files.
 */
static void
key_generate_secret(struct nyfe_xchacha20 *cipher, struct nyfe_kmac256 *kmac,
    const u_int8_t *seed, size_t seed_len)
{
	struct nyfe_kmac256	kdf;
	char			passphrase[256];
	const u_int8_t		*salt_kdf, *salt_prf;
	u_int8_t		key[NYFE_KEY_LEN], okm[NYFE_OKM_LEN];

	PRECOND(cipher != NULL);
	PRECOND(kmac != NULL);
	PRECOND(seed != NULL);
	PRECOND(seed_len == NYFE_SEED_LEN);

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(passphrase, sizeof(passphrase));

	nyfe_mem_zero(passphrase, sizeof(passphrase));
	if (readpassphrase("passphrase:", passphrase, sizeof(passphrase),
	    RPP_ECHO_OFF | RPP_REQUIRE_TTY) == NULL)
		fatal("failed to read passphrase");

	printf("deriving key material ... ");
	fflush(stdout);

	salt_kdf = &seed[0];
	salt_prf = &seed[KEY_FILE_SALT_LEN];

	key_passphrase_kdf(passphrase, sizeof(passphrase),
	    salt_kdf, KEY_FILE_SALT_LEN, key, sizeof(key));
	nyfe_zeroize(passphrase, sizeof(passphrase));

	printf("done\n");

	nyfe_kmac256_init(&kdf, key, sizeof(key),
	    KDF_DERIVE_LABEL, sizeof(KDF_DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kdf, salt_prf, KEY_FILE_SALT_LEN);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));

	nyfe_crypto_init(cipher, kmac, okm, sizeof(okm), KDF_INTEGRITY_LABEL);

	nyfe_zeroize(key, sizeof(key));
	nyfe_zeroize(okm, sizeof(okm));
}

/*
 * Derives a 256-bit key from the given passphrase and salt using
 * SHAKE256, XChaCha20 and KMAC256 using a large amount of memory.
 * and pseudorandom access patterns.
 */
static void
key_passphrase_kdf(const void *passphrase, u_int32_t passphrase_len,
    const void *salt, size_t salt_len, u_int8_t *out, size_t out_len)
{
	u_int16_t			*ap;
	u_int32_t			iter;
	struct nyfe_kmac256		kmac;
	struct nyfe_sha3		shake;
	struct nyfe_xchacha20		stream;
	size_t				idx, offset;
	u_int8_t			*tmp, buf[512];

	PRECOND(passphrase != NULL);
	PRECOND(salt != NULL);
	PRECOND(salt_len == KEY_FILE_SALT_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == 32);

	/* Allocate large intermediate buffers. */
	if ((tmp = calloc(1, PASSPHRASE_KDF_MEM_SIZE)) == NULL)
		fatal("failed to allocate temporary kdf buffer");
	if ((ap = calloc(1, PASSPHRASE_KDF_AP_SIZE)) == NULL)
		fatal("failed to allocate temporary kdf access patterns");

	/* Register buffers / structs that contain sensitive information. */
	nyfe_zeroize_register(buf, sizeof(buf));
	nyfe_zeroize_register(&kmac, sizeof(kmac));
	nyfe_zeroize_register(&shake, sizeof(shake));
	nyfe_zeroize_register(&stream, sizeof(stream));
	nyfe_zeroize_register(ap, PASSPHRASE_KDF_AP_SIZE);
	nyfe_zeroize_register(tmp, PASSPHRASE_KDF_MEM_SIZE);

	/*
	 * Run the passphrase and the salt through SHAKE256() to obtain
	 * 256 bytes of output. This output is used to generate the
	 * intermediate plaintext data, and the access patterns.
	 */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &passphrase_len, sizeof(passphrase_len));
	nyfe_sha3_update(&shake, passphrase, passphrase_len);
	nyfe_sha3_update(&shake, salt, salt_len);
	nyfe_sha3_final(&shake, buf, sizeof(buf));

	/* Generate access patterns based on first half of buf. */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &buf[0], sizeof(buf) / 2);
	nyfe_sha3_final(&shake, (u_int8_t *)ap, PASSPHRASE_KDF_AP_SIZE);

	/*
	 * Generate the intermediate plaintext data using the second half
	 * of buf and encrypt it under XChaCha20.
	 */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &buf[sizeof(buf) / 2], sizeof(buf) / 2);
	nyfe_sha3_final(&shake, tmp, PASSPHRASE_KDF_MEM_SIZE);

	nyfe_xchacha20_setup(&stream, &buf[0], 32, &buf[32], 24);
	nyfe_xchacha20_encrypt(&stream, tmp, tmp, PASSPHRASE_KDF_MEM_SIZE);
	nyfe_zeroize(&stream, sizeof(stream));

	/* Using nyfe_mem_zero() here since buf is still used later. */
	nyfe_mem_zero(buf, sizeof(buf));

	/*
	 * For each iteration:
	 *	- Grab the access location from ap.
	 *	- buf <- SHAKE256(iteration || ap || tmp[ap])
	 *	- tmp[ap] ^= buf
	 */
	for (iter = 0; iter < PASSPHRASE_KDF_ITERATIONS; iter++) {
		offset = ap[iter] * PASSPHRASE_KDF_STEP_LEN;

		nyfe_xof_shake256_init(&shake);
		nyfe_sha3_update(&shake, &iter, sizeof(iter));
		nyfe_sha3_update(&shake, &tmp[offset], PASSPHRASE_KDF_STEP_LEN);
		nyfe_sha3_final(&shake, buf, PASSPHRASE_KDF_STEP_LEN);

		for (idx = 0; idx < PASSPHRASE_KDF_STEP_LEN; idx++)
			tmp[offset] ^= buf[idx];
	}

	/* No longer need any of these intermediates. */
	nyfe_zeroize(buf, sizeof(buf));
	nyfe_zeroize(&shake, sizeof(shake));

	/*
	 * Use KMAC256() to derive the requested okm.
	 *
	 * The first 32 bytes of the tmp data is used as K for KMAC256
	 * while the remainder is used as X.
	 */
	nyfe_kmac256_init(&kmac, tmp, 32,
	    PASSPHRASE_DERIVE_LABEL, sizeof(PASSPHRASE_DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kmac, &tmp[32], PASSPHRASE_KDF_MEM_SIZE - 32);
	nyfe_kmac256_final(&kmac, out, out_len);
	nyfe_zeroize(&kmac, sizeof(kmac));

	nyfe_zeroize(tmp, PASSPHRASE_KDF_MEM_SIZE);
	nyfe_zeroize(ap, PASSPHRASE_KDF_AP_SIZE);

	free(ap);
	free(tmp);
}
