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

/*
 * The base key material used is stored in a file that is by default
 * located at $HOME/.nyfe/keys.
 *
 * The format of the key file is kept simple and is as follows:
 *
 *	[keyfile_id]			<-|
 *	[salt]				  |
 *	[iv]				  |
 *	[key_entry_0]			  | Integrity protected under K_i.
 *	[key_entry_1]			  |
 *	...				  |
 *	[key_entry_N]			<-|
 *	[keyfile_integrity_mac]
 *
 * Where key_entry is a single entry for a symmetrical key consisting of:
 *	[key_name (32 bytes)]
 *	[key_mass (32 bytes)]
 *
 * The key file is confidentiality is protected under AES256-CBC while
 * its integrity is protected using HMAC-SHA256.
 *
 * The key material used to protect the key file its confidentiality and
 * integrity are derived from a user supplied passphrase:
 *
 *	base = PBKDF(passphrase)
 *	prk = HKDF-Extract(base, salt, 256)
 *	K_c, K_i = HKDF-Expand(prk, "nyfe.keyfile", 512)
 */
