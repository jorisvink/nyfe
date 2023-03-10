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
#include <sys/stat.h>

#include <fcntl.h>
#include <unistd.h>

#include "nyfe.h"

int
nyfe_file_open(const char *path, int which)
{
	int		fd;
	struct stat	st;

	PRECOND(path != NULL);
	PRECOND(which == NYFE_FILE_READ || which == NYFE_FILE_CREATE);

	if (which == NYFE_FILE_READ) {
		if ((fd = open(path, O_RDONLY | O_NOFOLLOW)) == -1)
			fatal("failed to open '%s': %s", path, errno_s);

		if (fstat(fd, &st) == -1)
			fatal("fstat failed: %s", errno_s);

		if (!S_ISREG(st.st_mode))
			fatal("%s: not a file", path);
	} else {
		if (stat(path, &st) != -1)
			fatal("%s: already exists", path);

		if ((fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0500)) == -1)
			fatal("failed to open '%s': %s", path, errno_s);
	}

	return (fd);
}

u_int64_t
nyfe_file_size(int fd)
{
	struct stat	st;

	PRECOND(fd >= 0);

	if (fstat(fd, &st) == -1)
		fatal("fstat failed: %s", errno_s);

	return ((u_int64_t)st.st_size);
}

void
nyfe_file_write(int fd, const void *buf, size_t len)
{
	ssize_t		ret;

	PRECOND(fd >= 0);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	for (;;) {
		ret = write(fd, buf, len);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("write: %s", errno_s);
		}

		if ((size_t)ret != len)
			fatal("write: %zd/%zu", ret, len);

		break;
	}
}

size_t
nyfe_file_read(int fd, void *buf, size_t len)
{
	ssize_t		ret;

	PRECOND(fd >= 0);
	PRECOND(buf != NULL);
	PRECOND(len > 0);

	for (;;) {
		ret = read(fd, buf, len);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			fatal("read: %s", errno_s);
		}
		break;
	}

	return ((size_t)ret);
}
