# nyfe Makefile

CC?=cc
OBJDIR?=obj

BIN=nyfe

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude

CFLAGS+=-fsanitize=address,undefined
LDFLAGS+=-fsanitize=address,undefined

SRC=	src/nyfe.c \
	src/crypto.c \
	src/file.c \
	src/keccak1600.c \
	src/keys.c \
	src/kmac256.c \
	src/mem.c \
	src/sha3.c \
	src/random.c \
	src/selftest.c \
	src/xchacha20.c

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)

all: $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)
