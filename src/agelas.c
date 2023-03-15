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

#include <stdio.h>
#include <stdlib.h>

#include "nyfe.h"

/*
 * Agelas: An experimental, simple and fully authenticated stream cipher
 * based on Keccak1600. This work is based on Keyak, Spongewrap etc.
 *
 * init(key, nonce):
 *	K = bytepad(len(key) || key || 0x01, 136)
 *	State <- Keccak1600.init(K)
 *
 * encryption(pt):
 *	for each 136 byte block, do
 *		C = bytepad(counter, 136)
 *		counter = counter + 1
 *		Keccak1600.absorb(C)
 *		Keccak1600.absorb(State)
 *		State <- Keccak1600.squeeze(136)
 *		for i = 0 -> i = 136, do
 *			ct[i] = pt[i] ^ State[i]
 *			State[i] = State[i] ^ pt[i]
 *
 * decryption(ct):
 *	for each 136 byte block, do
 *		C = bytepad(counter, 136)
 *		counter = counter + 1
 *		Keccak1600.absorb(C)
 *		Keccak1600.absorb(State)
 *		State <- Keccak1600.squeeze(136)
 *		for i = 0 -> i = 136, do
 *			pt[i] = ct[i] ^ State[i]
 *			State[i] = State[i] ^ pt[i]
 *
 * Additional Authenticated Data may be added at beginning or
 * end of the stream and must fit in a single agelas_bytepad() block.
 *
 * add_aad(aad):
 *	Keccak1600.absorb(bytepad(aad, 136))
 *
 * The authentication tag is obtained at the end.
 *
 * authenticate(tag, taglen):
 *	C = bytepad(counter, 136)
 *	counter = counter + 1
 *	Keccak1600.absorb(C)
 *	Keccak1600.absorb(State)
 *	tag <- Keccak1600.squeeze(taglen)
 */

#define AGELAS_KECCAK_BITS	512
#define AGELAS_SPONGE_RATE	136
#define AGELAS_ABSORB_LEN	(AGELAS_SPONGE_RATE - 2)

static void	agelas_absorb_state(struct nyfe_agelas *);
static void	agelas_bytepad(const void *, size_t, u_int8_t *, size_t);

/*
 * Initializes an Agelas context with the given key.
 */
void
nyfe_agelas_init(struct nyfe_agelas *ctx, const void *key, size_t key_len)
{
	u_int8_t		buf[AGELAS_SPONGE_RATE];
	u_int8_t		padded[AGELAS_SPONGE_RATE];

	PRECOND(ctx != NULL);
	PRECOND(key != NULL);
	PRECOND(key_len == NYFE_KEY_LEN);

	nyfe_mem_zero(ctx, sizeof(*ctx));

	nyfe_zeroize_register(buf, sizeof(buf));
	nyfe_zeroize_register(padded, sizeof(padded));

	/*
	 * Construct input K that is to be absorbed into the initial state.
	 *	K = bytepad(len(key) || key || 0x01, 136)
	 */
	memcpy(buf, &key_len, sizeof(key_len));
	memcpy(&buf[sizeof(key_len)], key, key_len);

	agelas_bytepad(buf, sizeof(key_len) + key_len, padded, sizeof(padded));
	padded[AGELAS_SPONGE_RATE - 1] = 0x01;

	/* Absorb K into keccak sponge. */
	nyfe_keccak1600_init(&ctx->sponge, 0, AGELAS_KECCAK_BITS);
	nyfe_keccak1600_absorb(&ctx->sponge, padded, sizeof(padded));

	/* Generate first state. */
	ctx->offset = 0;
	nyfe_keccak1600_squeeze(&ctx->sponge, ctx->state, sizeof(ctx->state));

	nyfe_zeroize(buf, sizeof(buf));
	nyfe_zeroize(padded, sizeof(padded));
}

/*
 * Encrypt and authenticate plaintext given in `in` to the `out` buffer.
 * These buffers may be the same.
 */
void
nyfe_agelas_encrypt(struct nyfe_agelas *ctx, const void *in,
    void *out, size_t len)
{
	size_t			idx;
	const u_int8_t		*src;
	u_int8_t		tmp, *dst;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(len > 0);

	src = in;
	dst = out;

	for (idx = 0; idx < len; idx++) {
		if (ctx->offset == sizeof(ctx->state))
			agelas_absorb_state(ctx);
		tmp = src[idx];
		dst[idx] = tmp ^ ctx->state[ctx->offset];
		ctx->state[ctx->offset++] ^= tmp;
	}
}

/*
 * Decrypt and authenticate plaintext given in `in` to the `out` buffer.
 * These buffers may be the same.
 */
void
nyfe_agelas_decrypt(struct nyfe_agelas *ctx, const void *in,
    void *out, size_t len)
{
	size_t			idx;
	u_int8_t		*dst;
	const u_int8_t		*src;

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(len > 0);

	src = in;
	dst = out;

	for (idx = 0; idx < len; idx++) {
		if (ctx->offset == sizeof(ctx->state))
			agelas_absorb_state(ctx);
		dst[idx] = src[idx] ^ ctx->state[ctx->offset];
		ctx->state[ctx->offset++] ^= dst[idx];
	}
}

/*
 * Add additional authenticated data into the Agelas context.
 * The data its length must be 0 < len <= 134.
 */
void
nyfe_agelas_aad(struct nyfe_agelas *ctx, const void *data, size_t len)
{
	u_int8_t	buf[AGELAS_SPONGE_RATE];

	PRECOND(ctx != NULL);
	PRECOND(data != NULL);
	PRECOND(len <= AGELAS_ABSORB_LEN);

	agelas_bytepad(data, len, buf, sizeof(buf));
	nyfe_keccak1600_absorb(&ctx->sponge, buf, sizeof(buf));
}

/*
 * Obtain the tag from the Agelas context.
 */
void
nyfe_agelas_authenticate(struct nyfe_agelas *ctx, u_int8_t *tag, size_t len)
{
	PRECOND(ctx != NULL);
	PRECOND(tag != NULL);
	PRECOND(len == NYFE_TAG_LEN);

	agelas_absorb_state(ctx);
	nyfe_keccak1600_squeeze(&ctx->sponge, tag, len);
}

/*
 * Absorb the current state into the Keccak1600 and squeeze out a new one.
 */
static void
agelas_absorb_state(struct nyfe_agelas *ctx)
{
	u_int64_t	counter;
	u_int8_t	buf[AGELAS_SPONGE_RATE];

	PRECOND(ctx != NULL);

	counter = htobe64(ctx->counter);
	agelas_bytepad(&counter, sizeof(counter), buf, sizeof(buf));

	nyfe_keccak1600_absorb(&ctx->sponge, buf, sizeof(buf));
	nyfe_keccak1600_absorb(&ctx->sponge, ctx->state, sizeof(ctx->state));
	nyfe_keccak1600_squeeze(&ctx->sponge, ctx->state, sizeof(ctx->state));

	ctx->offset = 0;
	ctx->counter++;
}

/*
 * Helper function to bytepad() the given input to AGELAS_SPONGE_RATE bytes.
 */
static void
agelas_bytepad(const void *in, size_t inlen, u_int8_t *out, size_t outlen)
{
	PRECOND(in != NULL);
	PRECOND(inlen <= AGELAS_ABSORB_LEN);
	PRECOND(out != NULL);
	PRECOND(outlen == AGELAS_SPONGE_RATE);

	nyfe_mem_zero(out, outlen);
	out[0] = 0x01;
	out[1] = AGELAS_SPONGE_RATE;

	memcpy(&out[2], in, inlen);
}
