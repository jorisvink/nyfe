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
#include <sys/stat.h>

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
 *	K = nyfe_passphrase_kdf(passphrase, Rs[0..31])[64]
 *	Kc = KMAC256(K, Rs[32..64], "NYFE.KEYFILE.KDF")
 *	ct, tag = Agelas(Kc, Id || Kb)
 */

/* KMAC256 customization string for KDF. */
#define KDF_DERIVE_LABEL		"NYFE.KEYFILE.KDF"

/* KMAC256 customization string when deriving passphrase based keys. */
#define KDF_PASSPHRASE_LABEL		"NYFE.PASSPHRASE.KDF"

static void	key_generate_secret(struct nyfe_agelas *,
		    const u_int8_t *, size_t);

/*
 * Attempt to verify and decrypt a Nyfe key in the given file.
 * If successfull the key is returned via the `key` argument.
 *
 * If red is 1 and the given key file is the size of NYFE_KEY_LEN
 * we read the key as-is from it and use that.
 */
void
nyfe_key_load(struct nyfe_key *key, const char *file, int red)
{
	int				fd;
	struct stat			st;
	struct nyfe_agelas		cipher;
	u_int8_t			tag[NYFE_TAG_LEN];
	u_int8_t			seed[NYFE_SEED_LEN];

	PRECOND(key != NULL);
	PRECOND(file != NULL);
	PRECOND(red == 1 || red == 0);

	/* Open the suspected keyfile, read in the seed and key. */
	fd = nyfe_file_open(file, NYFE_FILE_READ);
	if (fstat(fd, &st) == -1)
		nyfe_fatal("fstat on '%s' failed: %s", file, errno_s);

	nyfe_zeroize_register(key, sizeof(*key));

	/* Handle red keys. */
	if (red == 1) {
		if (st.st_size != sizeof(key->data))
			nyfe_fatal("red key expected, but not found");

		nyfe_mem_zero(key, sizeof(*key));

		if (nyfe_file_read(fd,
		    key->data, sizeof(key->data)) != sizeof(key->data))
			nyfe_fatal("failed to read key from %s", file);

		(void)close(fd);

		nyfe_output("using red key '%s'\n", file);
		return;
	}

	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_output("unlocking keyfile '%s'\n", file);

	if (nyfe_file_read(fd, seed, sizeof(seed)) != sizeof(seed))
		nyfe_fatal("failed to read seed from %s", file);
	if (nyfe_file_read(fd, key, sizeof(*key)) != sizeof(*key))
		nyfe_fatal("failed to read key data from %s", file);

	/* Generate key material for decryption. */
	key_generate_secret(&cipher, seed, sizeof(seed));

	/* Decrypt and verify integrity. */
	nyfe_agelas_aad(&cipher, key->id, sizeof(key->id));
	nyfe_agelas_decrypt(&cipher, key->data, key->data, sizeof(key->data));
	nyfe_agelas_authenticate(&cipher, tag, sizeof(tag));

	if (nyfe_mem_cmp(tag, key->tag, sizeof(tag)) != 0)
		nyfe_fatal("integrity check on '%s' failed", file);

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

	/* Register sensitive data. */
	nyfe_zeroize_register(&key, sizeof(key));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

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

	nyfe_zeroize(&key, sizeof(key));
	nyfe_zeroize(&cipher, sizeof(cipher));

	nyfe_file_close(fd);
}

/*
 * Prompt for a passphrase from which an encryption key is derived.
 */
void
nyfe_key_from_passphrase(struct nyfe_key *key)
{
	struct nyfe_kmac256	kdf;
	char			passphrase[256];
	u_int8_t		salt[NYFE_KEY_FILE_SALT_LEN];

	PRECOND(key != NULL);

	/* Register sensitive data. */
	nyfe_zeroize_register(key, sizeof(*key));
	nyfe_zeroize_register(&kdf, sizeof(kdf));
	nyfe_zeroize_register(passphrase, sizeof(passphrase));

	nyfe_mem_zero(key, sizeof(*key));
	nyfe_mem_zero(salt, sizeof(salt));
	nyfe_mem_zero(passphrase, sizeof(passphrase));
	nyfe_read_passphrase(passphrase, sizeof(passphrase));

	nyfe_output("deriving encryption key from passphrase ... |");

	/* The salt passed is all zeroes. */
	nyfe_passphrase_kdf(passphrase, sizeof(passphrase),
	    salt, sizeof(salt), key->data, sizeof(key->data),
	    KDF_PASSPHRASE_LABEL, sizeof(KDF_PASSPHRASE_LABEL) - 1);

	/* Now run the intermediate key through KMAC256. */
	nyfe_kmac256_init(&kdf, key->data, sizeof(key->data),
	    KDF_PASSPHRASE_LABEL, sizeof(KDF_PASSPHRASE_LABEL) - 1);
	nyfe_kmac256_final(&kdf, key->data, sizeof(key->data));

	nyfe_output("\bdone\n");

	/* Don't call nyfe_zeroize() on key as the caller will use it. */
	nyfe_zeroize(&kdf, sizeof(kdf));
	nyfe_zeroize(passphrase, sizeof(passphrase));
}

/*
 * Clone an existing key from one keyfile to another keyfile.
 */
void
nyfe_key_clone(const char *in, const char *out)
{
	struct nyfe_key		key;

	PRECOND(in != NULL);
	PRECOND(out != NULL);

	nyfe_key_load(&key, in, 0);
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
	salt_prf = &seed[NYFE_KEY_FILE_SALT_LEN];

	nyfe_passphrase_kdf(passphrase, sizeof(passphrase),
	    salt_kdf, NYFE_KEY_FILE_SALT_LEN, key, sizeof(key),
	    KDF_PASSPHRASE_LABEL, sizeof(KDF_PASSPHRASE_LABEL) - 1);
	nyfe_zeroize(passphrase, sizeof(passphrase));

	nyfe_output("\bdone\n");

	len = NYFE_KEY_FILE_SALT_LEN;

	nyfe_kmac256_init(&kdf, key, sizeof(key),
	    KDF_DERIVE_LABEL, sizeof(KDF_DERIVE_LABEL) - 1);
	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, salt_prf, NYFE_KEY_FILE_SALT_LEN);
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));

	nyfe_agelas_init(cipher, okm, sizeof(okm));

	nyfe_zeroize(key, sizeof(key));
	nyfe_zeroize(okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));
}
