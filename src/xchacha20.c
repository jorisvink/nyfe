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

#include "nyfe.h"

#define ROTL32(v, b)	((v << b) | (v >> (32 - b)))

#define QUARTERROUND(a, b, c, d)					\
	do {								\
		a = a + b; d = d ^ a; d = ROTL32(d, 16U);		\
		c = c + d; b = b ^ c; b = ROTL32(b, 12U);		\
		a = a + b; d = d ^ a; d = ROTL32(d, 8U);		\
		c = c + d; b = b ^ c; b = ROTL32(b, 7U);		\
	} while (0)

static u_int32_t	bytestole32(const u_int8_t *);
static void		le32tobytes(const u_int32_t, u_int8_t *);

static void	xchacha20_rounds(struct nyfe_xchacha20 *,
		    struct nyfe_xchacha20 *);
static void	xchacha20_generate(struct nyfe_xchacha20 *,
		    u_int8_t *, size_t);

static const u_int8_t sigma[16] = {
	0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
	0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b
};

void
nyfe_xchacha20_setup(struct nyfe_xchacha20 *ctx, const u_int8_t *key,
    size_t key_len, const u_int8_t *iv, size_t iv_len)
{
	int				i;
	struct nyfe_xchacha20		subctx;

	PRECOND(ctx != NULL);
	PRECOND(key != NULL);
	PRECOND(key_len == 32);
	PRECOND(iv != NULL);
	PRECOND(iv_len == 24);

	/*
	 * Setup the input block using the specified key and first 128 bits
	 * of the nonce (instead of the block counters).
	 */
	ctx->input[0] = bytestole32(&sigma[0]);
	ctx->input[1] = bytestole32(&sigma[4]);
	ctx->input[2] = bytestole32(&sigma[8]);
	ctx->input[3] = bytestole32(&sigma[12]);

	ctx->input[4] = bytestole32(&key[0]);
	ctx->input[5] = bytestole32(&key[4]);
	ctx->input[6] = bytestole32(&key[8]);
	ctx->input[7] = bytestole32(&key[12]);

	ctx->input[8] = bytestole32(&key[16]);
	ctx->input[9] = bytestole32(&key[20]);
	ctx->input[10] = bytestole32(&key[24]);
	ctx->input[11] = bytestole32(&key[28]);

	ctx->input[12] = bytestole32(&iv[0]);
	ctx->input[13] = bytestole32(&iv[4]);

	ctx->input[14] = bytestole32(&iv[8]);
	ctx->input[15] = bytestole32(&iv[12]);

	/* Derive a subkey from the input block. */
	for (i = 0; i < 16; i++)
		subctx.input[i] = ctx->input[i];

	xchacha20_rounds(&subctx, &subctx);

	/*
	 * The subkey is the first and last row of the generated block.
	 *
	 * We now reconstruct our original input block, this time with the
	 * new subkey and the remainder of the nonce.
	 */
	ctx->input[4] = subctx.input[0];
	ctx->input[5] = subctx.input[1];
	ctx->input[6] = subctx.input[2];
	ctx->input[7] = subctx.input[3];

	ctx->input[8] = subctx.input[12];
	ctx->input[9] = subctx.input[13];
	ctx->input[10] = subctx.input[14];
	ctx->input[11] = subctx.input[15];

	ctx->input[12] = 0;
	ctx->input[13] = 0;

	ctx->input[14] = bytestole32(&iv[16]);
	ctx->input[15] = bytestole32(&iv[20]);

	nyfe_mem_zero(&subctx, sizeof(subctx));
}

void
nyfe_xchacha20_encrypt(struct nyfe_xchacha20 *ctx, const void *in,
    void *out, size_t len)
{
	u_int8_t		*ct;
	const u_int8_t		*pt;
	size_t			idx;
	u_int8_t		block[64];

	PRECOND(ctx != NULL);
	PRECOND(in != NULL);
	PRECOND(out != NULL);
	PRECOND(len > 0);

	pt = in;
	ct = out;

	for (;;) {
		xchacha20_generate(ctx, block, sizeof(block));

		ctx->input[12] += 1;
		if (ctx->input[12] == 0)
			ctx->input[13] += 1;

		if (len <= 64) {
			for (idx = 0; idx < len; idx++)
				ct[idx] = pt[idx] ^ block[idx];
			break;
		}

		for (idx = 0; idx < sizeof(block); idx++)
			ct[idx] = pt[idx] ^ block[idx];

		len -= sizeof(block);
		ct += sizeof(block);
		pt += sizeof(block);
	}

	nyfe_mem_zero(block, sizeof(block));
}

static void
xchacha20_generate(struct nyfe_xchacha20 *ctx, u_int8_t *output, size_t len)
{
	int				i;
	struct nyfe_xchacha20		subctx;
	u_int32_t			tmp[16];

	PRECOND(ctx != NULL);
	PRECOND(output != NULL);
	PRECOND(len == 64);

	for (i = 0; i < 16; i++)
		tmp[i] = ctx->input[i];

	xchacha20_rounds(ctx, &subctx);

	for (i = 0; i < 16; i++)
		subctx.input[i] += ctx->input[i];

	for (i = 0; i < 16; i++)
		le32tobytes(subctx.input[i], &output[i * 4]);

	nyfe_mem_zero(tmp, sizeof(tmp));
	nyfe_mem_zero(&subctx, sizeof(subctx));
}

static void
xchacha20_rounds(struct nyfe_xchacha20 *in, struct nyfe_xchacha20 *out)
{
	int		i;
	u_int32_t	tmp[16];

	PRECOND(in != NULL);
	PRECOND(out != NULL);

	for (i = 0; i < 16; i++)
		tmp[i] = in->input[i];

	for (i = 0; i < 10; i++) {
		/* Columns. */
		QUARTERROUND(tmp[0], tmp[4], tmp[8], tmp[12]);
		QUARTERROUND(tmp[1], tmp[5], tmp[9], tmp[13]);
		QUARTERROUND(tmp[2], tmp[6], tmp[10], tmp[14]);
		QUARTERROUND(tmp[3], tmp[7], tmp[11], tmp[15]);

		/* Diagonal. */
		QUARTERROUND(tmp[0], tmp[5], tmp[10], tmp[15]);
		QUARTERROUND(tmp[1], tmp[6], tmp[11], tmp[12]);
		QUARTERROUND(tmp[2], tmp[7], tmp[8], tmp[13]);
		QUARTERROUND(tmp[3], tmp[4], tmp[9], tmp[14]);
	}

	for (i = 0; i < 16; i++)
		out->input[i] = tmp[i];

	nyfe_mem_zero(tmp, sizeof(tmp));
}

static u_int32_t
bytestole32(const u_int8_t *data)
{
	u_int32_t	v;

	PRECOND(data != NULL);

	v = ((u_int32_t)data[0] |
	    ((u_int32_t)data[1] << 8U) |
	    ((u_int32_t)data[2] << 16U) |
	    ((u_int32_t)data[3] << 24U));

	return (v);
}

static void
le32tobytes(const u_int32_t val, u_int8_t *out)
{
	PRECOND(out != NULL);

	out[0] = val;
	out[1] = (u_int8_t)(val >> 8U);
	out[2] = (u_int8_t)(val >> 16U);
	out[3] = (u_int8_t)(val >> 24U);
}
