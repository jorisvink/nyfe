# tests Makefile

CC?=cc
AR?=ar
OBJDIR?=obj

BIN=sha3_tests
LIB=../libnyfe.a

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -I../include
CFLAGS+=-fno-builtin -g

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
	LDFLAGS+=-lbsd
endif

SRC=	sha3_tests.c

OBJS=	$(SRC:%.c=$(OBJDIR)/%.o)

$(BIN): $(OBJDIR) $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN) $(LIB)

keccak-tests: $(BIN)
	./sha3_tests -c 256 sha-3bytetestvectors/SHA3_256LongMsg.rsp
	./sha3_tests -c 256 sha-3bytetestvectors/SHA3_256ShortMsg.rsp
	./sha3_tests -c 512 sha-3bytetestvectors/SHA3_512LongMsg.rsp
	./sha3_tests -c 512 sha-3bytetestvectors/SHA3_512ShortMsg.rsp
	./sha3_tests -m -c 256 sha-3bytetestvectors/SHA3_256Monte.rsp
	./sha3_tests -m -c 512 sha-3bytetestvectors/SHA3_512Monte.rsp

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean force
