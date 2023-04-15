# nyfe Makefile

CC?=cc
OBJDIR?=obj

BIN=nyfe
VERSION=$(OBJDIR)/version.c

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif

SRC=	src/nyfe.c \
	src/agelas.c \
	src/crypto.c \
	src/file.c \
	src/keccak1600.c \
	src/keys.c \
	src/kmac256.c \
	src/mem.c \
	src/sha3.c \
	src/random.c \
	src/selftest.c

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

install: $(BIN)
	install -m 555 $(BIN) /usr/local/bin/$(BIN)

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
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean force
