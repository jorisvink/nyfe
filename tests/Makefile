# tests Makefile

CC?=cc
AR?=ar

BIN=sha3_tests shake_tests
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

all: $(BIN)

sha3_tests: sha3_tests.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LIB)

shake_tests: shake_tests.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LIB)

keccak-tests: $(BIN)
	./sha3_tests -c 256 sha-3bytetestvectors/SHA3_256LongMsg.rsp
	./sha3_tests -c 256 sha-3bytetestvectors/SHA3_256ShortMsg.rsp
	./sha3_tests -c 512 sha-3bytetestvectors/SHA3_512LongMsg.rsp
	./sha3_tests -c 512 sha-3bytetestvectors/SHA3_512ShortMsg.rsp
	./sha3_tests -m -c 256 sha-3bytetestvectors/SHA3_256Monte.rsp
	./sha3_tests -m -c 512 sha-3bytetestvectors/SHA3_512Monte.rsp
	./shake_tests -c 128 shakebytetestvectors/SHAKE128LongMsg.rsp
	./shake_tests -c 128 shakebytetestvectors/SHAKE128ShortMsg.rsp
	./shake_tests -c 256 shakebytetestvectors/SHAKE256LongMsg.rsp
	./shake_tests -c 256 shakebytetestvectors/SHAKE256ShortMsg.rsp
	./shake_tests -m -c 128 shakebytetestvectors/SHAKE128Monte.rsp
	./shake_tests -m -c 256 shakebytetestvectors/SHAKE256Monte.rsp

clean:
	rm -rf $(BIN)

.PHONY: all clean force
