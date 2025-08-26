# nyfe Makefile

CC?=cc
AR?=ar
OBJDIR?=obj

BIN=nyfe
LIB=libnyfe.a
VERSION=$(OBJDIR)/version.c

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-fno-builtin

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

ifeq ("$(OSNAME)", "")
OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
endif

ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "windows")
	CFLAGS+=-DNYFE_PLATFORM_WINDOWS
endif

SRC=	src/nyfe.c \
	src/crypto.c \
	src/keys.c \
	src/selftest.c

LIBSRC=	src/agelas.c \
	src/file.c \
	src/keccak1600.c \
	src/kmac256.c \
	src/mem.c \
	src/passphrase.c \
	src/sha3.c \
	src/random.c \
	src/utils.c

SRC+=	$(LIBSRC)

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

LIBOBJS=$(LIBSRC:src/%.c=$(OBJDIR)/%.o)
LIBOBJS+=$(OBJDIR)/version.o

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

lib:
	env CFLAGS=-DNYFE_LIBRARY_ONLY=1 $(MAKE) $(LIB)

$(LIB): $(OBJDIR) $(LIBOBJS)
	$(AR) rcs $(LIB) $(LIBOBJS)

install: $(BIN)
	install -m 555 $(BIN) /usr/local/bin/$(BIN)

keccak-tests: lib
	$(MAKE) -C tests keccak-tests

$(OBJDIR):
	@mkdir -p $(OBJDIR)

src/nyfe.c: $(VERSION)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(VERSION): $(OBJDIR) force
	@if [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION); \
		printf "const char *nyfe_version = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION); \
	elif [ -f RELEASE ]; then \
		printf "const char *nyfe_version = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION); \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *nyfe_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION);

clean:
	rm -rf $(OBJDIR) $(BIN) $(LIB)
	$(MAKE) -C tests clean

.PHONY: all clean force
