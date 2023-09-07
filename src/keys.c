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
 *	Ka = Key for Agelas (512-bit)
 * 	Rs = Random seed from keyfile (512-bit)
 *
 * To verify and decrypt a keyfile:
 *
 *	K = passphrase_kdf(passphrase, Rs[0..32])[64]
 *	Kc = KMAC256(K, seed, "NYFE.KEYFILE.KDF")
 *	ct, tag = Agelas(Kc, Id || Kb)
 *
 * The passphrase_kdf(passphrase, salt) function:
 *
 *	tmp = Intermediate buffer holding pseudorandom data
 *	ap = Pseudorandom generated list of accesses into tmp
 *	buf = SHAKE256(len(passphrase) || passphrase || salt)[512]
 *	Kt = 512-bit Agelas key to generate key stream (buf_0[0..64])
 *	Km = 256-bit KMAC256 key (tmp[0..32])
 *
 *	ap = SHAKE256(buf[0..256])[PASSPHRASE_KDF_AP_SIZE]
 *	tmp = SHAKE256(buf[256..512])[PASSPHRASE_KDF_MEM_SIZE]
 *	tmp = Agelas(Kt, tmp, aad=None)
 *
 *	for iter = 0, iter < PASSPHRASE_KDF_ITERATIONS; do
 *		offset = ap[iter] * PASSPHRASE_KDF_STEP_LEN
 *		if iter % 2048 == 0; do
 *			Agelas(Kt,tmp[offset..PASSPHRASE_KDF_MEM_SIZE - offset])
 *		tmp[offset..offset+256] ^= SHAKE256(tmp[0..256])
 *
 *	X = tmp[32..PASSPHRASE_KDF_MEM_SIZE]
 *	return KMAC256(Km, X, "NYFE.PASSPHRASE.KDF")[64]
 */

/* Passphrase KDF settings, will use 32MB memory, 65536 iterations. */
#define PASSPHRASE_KDF_ITERATIONS	65536
#define PASSPHRASE_KDF_MEM_SIZE		(1024 * 1024 * 32)
#define PASSPHRASE_KDF_STEP_LEN		\
    (PASSPHRASE_KDF_MEM_SIZE / PASSPHRASE_KDF_ITERATIONS)
#define PASSPHRASE_KDF_AP_SIZE		\
    (PASSPHRASE_KDF_ITERATIONS * sizeof(u_int16_t))
#define PASSPHRASE_DERIVE_LABEL		"NYFE.PASSPHRASE.KDF"

/* KMAC256 customization string for KDF. */
#define KDF_DERIVE_LABEL		"NYFE.KEYFILE.KDF"

/*
 * Half of the seed is used as a salt into key_passphrase_kdf() while
 * half of it is used as seed for key_kdf().
 */
#define KEY_FILE_SALT_LEN		(NYFE_SEED_LEN / 2)

static void	key_generate_secret(struct nyfe_agelas *,
		    const u_int8_t *, size_t);
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
	struct nyfe_agelas		cipher;
	u_int8_t			tag[NYFE_TAG_LEN];
	u_int8_t			seed[NYFE_SEED_LEN];

	PRECOND(key != NULL);
	PRECOND(file != NULL);

	nyfe_output("unlocking keyfile '%s'\n", file);

	/* Open the suspected keyfile, read in the seed and key. */
	fd = nyfe_file_open(file, NYFE_FILE_READ);
	if (nyfe_file_read(fd, seed, sizeof(seed)) != sizeof(seed))
		fatal("failed to read seed from %s", file);
	if (nyfe_file_read(fd, key, sizeof(*key)) != sizeof(*key))
		fatal("failed to read key data from %s", file);

	/* Register any sensitive buffers. */
	nyfe_zeroize_register(key, sizeof(*key));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	/* Generate key material for decryption. */
	key_generate_secret(&cipher, seed, sizeof(seed));

	/* Decrypt and verify integrity. */
	nyfe_agelas_aad(&cipher, key->id, sizeof(key->id));
	nyfe_agelas_decrypt(&cipher, key->data, key->data, sizeof(key->data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));

	if (nyfe_mem_cmp(tag, key->tag, sizeof(tag)) != 0)
		fatal("integrity check on '%s' failed", file);

	/* Don't call nyfe_zeroize() on key as the caller will use it. */
	nyfe_zeroize(&cipher, sizeof(cipher));

	(void)close(fd);
}

/*
 * Generate a new key into the given keyfile, or if curkey is not NULL,
 * generate a new keyfile with the contents of curkey.
 */
void
nyfe_key_generate(const char *file, struct nyfe_key *curkey)
{
	int				fd;
	struct nyfe_key			key;
	struct nyfe_agelas		cipher;
	u_int8_t			tag[NYFE_TAG_LEN];
	u_int8_t			seed[NYFE_SEED_LEN];

	PRECOND(file != NULL);
	/* curkey may be NULL to indicate a new key generation. */

	nyfe_output("creating keyfile '%s'\n", file);

	/* Open destination keyfile early so we can exit early. */
	fd = nyfe_file_open(file, NYFE_FILE_CREATE);

	/*
	 * If curkey is NULL:
	 *
	 * Generate the key ID and the key data, do a nyfe_random_init()
	 * in between so both outputs are not related to each other since
	 * id is stored in plaintext in the key file.
	 *
	 * Or if curkey was not NULL:
	 *
	 * Copy over the information instead of randomly creating it.
	 */
	if (curkey == NULL) {
		nyfe_random_bytes(key.id, sizeof(key.id));
		nyfe_random_init();
		nyfe_random_bytes(key.data, sizeof(key.data));
		nyfe_random_init();
	} else {
		nyfe_memcpy(key.id, curkey->id, sizeof(curkey->id));
		nyfe_memcpy(key.data, curkey->data, sizeof(curkey->data));
	}

	/* Generate random seed and derive key material for this file. */
	nyfe_random_bytes(seed, sizeof(seed));
	key_generate_secret(&cipher, seed, sizeof(seed));

	/* Encrypt and authenticate key data. */
	nyfe_agelas_aad(&cipher, key.id, sizeof(key.id));
	nyfe_agelas_encrypt(&cipher, key.data, key.data, sizeof(key.data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));

	/* Write all contents to the new keyfile. */
	nyfe_file_write(fd, seed, sizeof(seed));
	nyfe_file_write(fd, key.id, sizeof(key.id));
	nyfe_file_write(fd, key.data, sizeof(key.data));
	nyfe_file_write(fd, tag, sizeof(tag));

	nyfe_mem_zero(&key, sizeof(key));
	nyfe_mem_zero(&cipher, sizeof(cipher));

	nyfe_file_close(fd);
}

/*
 * Clone an existing key from one keyfile to another keyfile.
 */
void
nyfe_key_clone(const char *in, const char *out)
{
	struct nyfe_key		key;

	nyfe_key_load(&key, in);
	nyfe_key_generate(out, &key);

	nyfe_zeroize(&key, sizeof(key));
}

/*
 * Helper function to derive the required key material to setup the
 * Agelas context for confidentiality and integrity protection on key files.
 */
static void
key_generate_secret(struct nyfe_agelas *cipher, const u_int8_t *seed,
    size_t seed_len)
{
	struct nyfe_kmac256	kdf;
	u_int8_t		len;
	char			passphrase[256];
	const u_int8_t		*salt_kdf, *salt_prf;
	u_int8_t		key[NYFE_KEY_LEN], okm[NYFE_OKM_LEN];

	PRECOND(cipher != NULL);
	PRECOND(seed != NULL);
	PRECOND(seed_len == NYFE_SEED_LEN);

	nyfe_zeroize_register(key, sizeof(key));
	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(passphrase, sizeof(passphrase));

	nyfe_mem_zero(passphrase, sizeof(passphrase));
	nyfe_read_passphrase(passphrase, sizeof(passphrase));

	nyfe_output("deriving keys to verify and unlock keyfile ... |");

	salt_kdf = &seed[0];
	salt_prf = &seed[KEY_FILE_SALT_LEN];

	key_passphrase_kdf(passphrase, sizeof(passphrase),
	    salt_kdf, KEY_FILE_SALT_LEN, key, sizeof(key));
	nyfe_zeroize(passphrase, sizeof(passphrase));

	nyfe_output("\bdone\n");

	len = KEY_FILE_SALT_LEN;

	nyfe_kmac256_init(&kdf, key, sizeof(key),
	    KDF_DERIVE_LABEL, sizeof(KDF_DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, salt_prf, KEY_FILE_SALT_LEN);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));

	nyfe_agelas_init(cipher, okm, sizeof(okm));

	nyfe_zeroize(key, sizeof(key));
	nyfe_zeroize(okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));
}

/*
 * Derives a 256-bit key from the given passphrase and salt using
 * SHAKE256, Agelas and KMAC256 using a large amount of memory.
 * and pseudorandom access patterns.
 */
static void
key_passphrase_kdf(const void *passphrase, u_int32_t passphrase_len,
    const void *salt, size_t salt_len, u_int8_t *out, size_t out_len)
{
	u_int16_t			*ap;
	int				sig;
	struct nyfe_kmac256		kmac;
	struct nyfe_sha3		shake;
	struct nyfe_agelas		stream;
	size_t				idx, offset;
	u_int32_t			iter, counter;
	u_int8_t			*tmp, buf[512];

	PRECOND(passphrase != NULL);
	PRECOND(salt != NULL);
	PRECOND(salt_len == KEY_FILE_SALT_LEN);
	PRECOND(out != NULL);
	PRECOND(out_len == NYFE_KEY_LEN);

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
	 * 512 bytes of output. This output is used to generate the
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
	 * of buf and encrypt it under Agelas.
	 */
	nyfe_xof_shake256_init(&shake);
	nyfe_sha3_update(&shake, &buf[sizeof(buf) / 2], sizeof(buf) / 2);
	nyfe_sha3_final(&shake, tmp, PASSPHRASE_KDF_MEM_SIZE);

	nyfe_agelas_init(&stream, &buf[0], NYFE_KEY_LEN);
	nyfe_agelas_encrypt(&stream, tmp, tmp, PASSPHRASE_KDF_MEM_SIZE);

	/* Using nyfe_mem_zero() here since buf is still used later. */
	nyfe_mem_zero(buf, sizeof(buf));

	/*
	 * For each iteration:
	 *	- Grab the access location from ap.
	 *	- offset = ap * PASSPHRASE_KDF_STEP_LEN
	 *	- iter % 2048 == 0:
	 *		tmp[offset] <- Agelas(tmp[offset])
	 *	- buf <- SHAKE256(iteration || tmp[offset)
	 *	- tmp[offset] ^= buf
	 */
	for (iter = 0; iter < PASSPHRASE_KDF_ITERATIONS; iter++) {
		if ((sig = nyfe_signal_pending()) != -1)
			fatal("clean abort due to received signal %d", sig);

		offset = ap[iter] * PASSPHRASE_KDF_STEP_LEN;

		/*
		 * Every 2048th iteration run part of the intermediate data
		 * through the Agelas cipher.
		 */
		if ((iter % 2048) == 0) {
			nyfe_output_spin();
			nyfe_agelas_encrypt(&stream,
			    &tmp[offset], &tmp[offset],
			    PASSPHRASE_KDF_MEM_SIZE - offset);
		}

		counter = htobe32(iter);
		nyfe_xof_shake256_init(&shake);
		nyfe_sha3_update(&shake, &counter, sizeof(counter));
		nyfe_sha3_update(&shake, &tmp[offset], PASSPHRASE_KDF_STEP_LEN);
		nyfe_sha3_final(&shake, buf, PASSPHRASE_KDF_STEP_LEN);

		for (idx = 0; idx < PASSPHRASE_KDF_STEP_LEN; idx++)
			tmp[offset] ^= buf[idx];
	}

	/* No longer need any of these intermediates. */
	nyfe_zeroize(buf, sizeof(buf));
	nyfe_zeroize(&shake, sizeof(shake));
	nyfe_zeroize(&stream, sizeof(stream));

	/*
	 * Use KMAC256() to derive the requested okm.
	 *
	 * The first 32 bytes of the tmp data is used as K for KMAC256
	 * while the remainder is used as X.
	 */
	iter = htobe32(PASSPHRASE_KDF_MEM_SIZE - 32);
	nyfe_kmac256_init(&kmac, tmp, 32,
	    PASSPHRASE_DERIVE_LABEL, sizeof(PASSPHRASE_DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kmac, &iter, sizeof(iter));
	nyfe_kmac256_update(&kmac, &tmp[32], PASSPHRASE_KDF_MEM_SIZE - 32);
	nyfe_kmac256_final(&kmac, out, out_len);
	nyfe_zeroize(&kmac, sizeof(kmac));

	nyfe_zeroize(tmp, PASSPHRASE_KDF_MEM_SIZE);
	nyfe_zeroize(ap, PASSPHRASE_KDF_AP_SIZE);

	free(ap);
	free(tmp);
}
