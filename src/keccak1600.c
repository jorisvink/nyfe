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

#include <string.h>

#include "nyfe.h"

/*
 * An easy to read and verify Keccak1600 implementation.
 *
 * Note that due to C its arrays the x, y coordinates are reversed.
 */

#define rho(v)		((v % 64))

static u_int64_t	rotl64(u_int64_t, u_int64_t);

static void	keccak1600_pi(struct nyfe_keccak1600 *);
static void	keccak1600_rho(struct nyfe_keccak1600 *);
static void	keccak1600_chi(struct nyfe_keccak1600 *);
static void	keccak1600_theta(struct nyfe_keccak1600 *);
static void	keccak1600_rounds(struct nyfe_keccak1600 *);

/*
 * The Rho step bit shifting offsets for each coordinate in the matrix.
 * The rho() macro basically does mod 64 on these but this way they
 * are mappable to the standard.
 */
static const u_int8_t rho_offsets[5][5] = {
	{ rho(0), rho(1), rho(190), rho(28), rho(91) },
	{ rho(36), rho(300), rho(6), rho(55), rho(276) },
	{ rho(3), rho(10), rho(171), rho(153), rho(231) },
	{ rho(105), rho(45), rho(15), rho(21), rho(136) },
	{ rho(210), rho(66), rho(253), rho(120), rho(78) },
};

/*
 * Precalculated round constants for the Iota step.
 */
static const uint64_t iota_rc[] = {
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808a,
	0x8000000080008000,
	0x000000000000808b,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008a,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000a,
	0x000000008000808b,
	0x800000000000008b,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800a,
	0x800000008000000a,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};

/*
 * Initialize a keccak1600 context. The caller supplies the number of
 * bits its requesting. This in combination with the padding byte used
 * denotes the type. We only support 128, 256 and 512 bits.
 *
 * This means the following SHA3 constructs can be made:
 *
 *	SHA3-256(M) = KECCAK[512] (M || 01, 256);
 *	SHA3-384(M) = KECCAK[768] (M || 01, 384);
 *	SHA3-512(M) = KECCAK[1024] (M || 01, 512).
 *
 * and the following XOF constructs:
 *
 *	SHAKE128(M, d) = KECCAK[256] (M || 1111, d),
 *	SHAKE256(M, d) = KECCAK[512] (M || 1111, d).
 */
void
nyfe_keccak1600_init(struct nyfe_keccak1600 *ctx, u_int8_t pad, size_t bits)
{
	PRECOND(ctx != NULL);
	PRECOND(bits == 256 || bits == 512 || bits == 768 || bits == 1024);
	PRECOND(pad == '\x1f' || pad == '\x04' || pad == '\x06');

	nyfe_mem_zero(ctx, sizeof(*ctx));

	ctx->padding = pad;
	ctx->rate = (NYFE_KECCAK_1600_RATE - bits) / 8;
}

/*
 * Absorb data into the Keccak sponge.
 *
 * This is done at a fixed rate, this function will return the number
 * of lingering bytes it was unable to process.
 */
size_t
nyfe_keccak1600_absorb(struct nyfe_keccak1600 *ctx, const void *buf, size_t len)
{
	const u_int8_t		*ptr;
	size_t			i, b;
	u_int64_t		v, *array;

	PRECOND(ctx != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	ptr = buf;
	array = &ctx->A[0][0];

	while (len >= ctx->rate) {
		for (i = 0; i < (ctx->rate / 8); i++) {
			v = 0;

			for (b = 0; b < sizeof(v); b++)
				v |= (u_int64_t)ptr[b] << (b * 8);

			ptr += sizeof(v);
			array[i] ^= v;
		}

		keccak1600_rounds(ctx);
		len -= ctx->rate;
	}

	return (len);
}

/*
 * Squeeze out the requested amount of data from the sponge.
 */
void
nyfe_keccak1600_squeeze(struct nyfe_keccak1600 *ctx, void *buf, size_t len)
{
	u_int8_t		*ptr;
	u_int64_t		v, *array;
	size_t			i, b, left;

	PRECOND(ctx != NULL);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	ptr = buf;
	array = &ctx->A[0][0];

	while (len != 0) {
		for (i = 0; i < (ctx->rate / 8); i++) {
			v = array[i];
			left = MIN(sizeof(v), len);

			for (b = 0; b < left; b++)
				ptr[b] = (u_int8_t)(v >> (b * 8));

			len -= left;
			ptr += left;
		}

		if (len != 0)
			keccak1600_rounds(ctx);
	}
}

/*
 * Perform 24 rounds of Keccak: Theta, Rho, Pi, Chi, Iota.
 */
static void
keccak1600_rounds(struct nyfe_keccak1600 *ctx)
{
	size_t		round;

	PRECOND(ctx != NULL);

	for (round = 0; round < 24; round++) {
		keccak1600_theta(ctx);
		keccak1600_rho(ctx);
		keccak1600_pi(ctx);
		keccak1600_chi(ctx);

		/* Iota */
		ctx->A[0][0] ^= iota_rc[round];
	}
}

/* Rotate 64-bit integer left with carry. */
static u_int64_t
rotl64(u_int64_t v, u_int64_t b)
{
	if (b == 0)
		return (v);

	return ((v << b) | (v >> (64 - b)));
}

/*
 * The Theta step for the Keccak algorithm.
 */
static void
keccak1600_theta(struct nyfe_keccak1600 *ctx)
{
	int		y, x;
	u_int64_t	C[5], D[5];

	PRECOND(ctx != NULL);

	nyfe_mem_zero(C, sizeof(C));

	/*
	 * Theta step 1, from chapter 3.2.1
	 *	C[x,z]=A[x,0,z] ^ A[x,1,z] ^ A[x,2,z] ^ A[x,3,z] ^ A[x,4,z].
	 */
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
			C[x] ^= ctx->A[y][x];
		}
	}

	/*
	 * Theta step 2, from chapter 3.2.1
	 *	D[x, z]=C[(x - 1) mod 5, z] ^ C[(x+1) mod 5, (z –1) mod w].
	 */
	for (x = 0; x < 5; x++)
		D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);

	/*
	 * Theta step 3, from chapter 3.2.1
	 *	A[x,y,z] = A[x,y,z] ^ D[x,z].
	 */
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
			ctx->A[y][x] = ctx->A[y][x] ^ D[x];
		}
	}

	nyfe_mem_zero(C, sizeof(C));
	nyfe_mem_zero(D, sizeof(D));
}

/*
 * The Rho step for the Keccak algorithm.
 */
static void
keccak1600_rho(struct nyfe_keccak1600 *ctx)
{
	int		y, x;

	PRECOND(ctx != NULL);

	/*
	 * Rho step from chapter 3.2.2
	 *
	 * Essentially we rotate the bits in the A matrix based on
	 * an offset that depends on the x, y coordinates of the lane.
	 */
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
			ctx->A[y][x] = rotl64(ctx->A[y][x], rho_offsets[y][x]);
		}
	}
}

/*
 * The Pi step for the Keccak algorithm.
 */
static void
keccak1600_pi(struct nyfe_keccak1600 *ctx)
{
	int		y, x;
	u_int64_t	tmp[5][5];

	PRECOND(ctx != NULL);

	memcpy(tmp, ctx->A, sizeof(ctx->A));

	/*
	 * Pi step from chapter 3.2.3
	 *	A[x, y, z]= A[(x + 3y) mod 5, x, z].
	 */
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
			ctx->A[y][x] = tmp[x][(x + (3 * y)) % 5];
		}
	}

	nyfe_mem_zero(tmp, sizeof(tmp));
}

/*
 * The Chi step for the Keccak algorithm.
 */
static void
keccak1600_chi(struct nyfe_keccak1600 *ctx)
{
	int		y, x;
	u_int64_t	tmp[5][5];

	memcpy(tmp, ctx->A, sizeof(ctx->A));

	/*
	 * Chi step from chapter 3.2.3
	 *	A[x,y,z] = A[x,y,z] ^
	 *	    ((A[(x+1) mod 5, y, z] ^ 1) . A[(x+2) mod 5, y, z]).
	 */
	for (y = 0; y < 5; y++) {
		for (x = 0; x < 5; x++) {
			ctx->A[y][x] = ctx->A[y][x] ^
			    (~tmp[y][(x + 1) % 5] & tmp[y][(x + 2) % 5]);
		}
	}

	nyfe_mem_zero(tmp, sizeof(tmp));
}
