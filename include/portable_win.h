/*
 * Copyright (c) 2025 Joris Vink <joris@sanctorum.se>
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

#ifndef __H_NYFE_WINDOWS_H
#define __H_NYFE_WINDOWS_H

/*
 * This is the windows portability header allowing libnyfe
 * to compile on at least 64-bit windows platforms via mingw
 * based toolchains.
 */

#if !defined(__WIN64__) || !defined(__MINGW64__)
#error "portable_win.h is only for 64-bit windows platforms"
#endif

/* We want _WIN32_WINNT_WIN10 apis at least. */
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#include <sys/param.h>

#include <winsock2.h>
#include <ntsecapi.h>

#include <stdint.h>

/* libnyfe will use this to determine if we're on windows. */
#define NYFE_WINDOWS_PLATFORM		1

/*
 * Windows doesn't appear to have this simple macro which POSIX systems
 * carry in their sys/param.h header.
 */
#define MIN(a, b)	((a > b) ? b : a)

/*
 * Windows does not define O_NOFOLLOW, define it to be nothing so we
 * do not have to modify the open() code in nyfe_file_open() with
 * ugle defines.
 */
#define O_NOFOLLOW	0

/*
 * I like using BSD-style typedefs which windows does not carry, so
 * define them here.
 */
typedef uint8_t		u_int8_t;
typedef uint16_t	u_int16_t;
typedef uint32_t	u_int32_t;
typedef uint64_t	u_int64_t;

/* More sensible endian.h like calls. */
#define htobe16(x)	htons(x)
#define be16toh(x)	ntohs(x)
#define htobe32(x)	htonl(x)
#define be32toh(x)	ntohl(x)
#define htobe64(x)	htonll(x)
#define be64toh(x)	ntohll(x)

#endif
