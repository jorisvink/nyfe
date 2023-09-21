# Nyfe

A software based file encryption tool where all cryptographic parts
are based on a single cryptographic permutation: Keccak-f[1600,24].

Nyfe is very minimal and lightweight as it has no external dependencies.

# License

Nyfe is licensed under the ISC license.

# Cryptography

WARNING: Nyfe uses experimental sponge-based cryptography.

## Disclaimer

This is a personal research project of mine and at most it's a little broken.

**You** probably do not want to use this.

## Confidentiality and Integrity

Its confidentiality and integrity are protected under Agelas.

Agelas is an experimental Authenticated Encryption stream cipher
that is constructed with Keccak-f[1600,24] in combination with
a duplex-sponge.

## KDF

KMAC256 is used as a KDF for all derivations that take place.

KMAC256 is a NIST standard.

## Random

The random system in Nyfe is also based on Keccak.

In this case, it will instantiate an Agelas context with keys
that are derived from a random seed from the system which are
run through KMAC256.

It then allows random byte generation of up to 960 bytes before
rekeying itself.

An 64-byte ondisk entropy file under $HOME/.nyfe/entropy is mixed
in if available, in addition to system entropy.

The entropy file is rewritten immediately when used.
You're on your own to generate that file initially.

## Keys

The keys used with Agelas are derived from strong 256-bit symmetrical
secrets that are stored in key files.

Nyfe will generate a new key per file that is to be encrypted by selecting
a seed uniformly at random and using it in combination with the symmetrical
key from the given key file to derive new key material via KMAC256.

## Metadata

The lack of meta-data in encrypted files is by design.

# Performance

Performance is not considered at this stage, code correctness
and extreme care in handling sensitive data was.

# Building

Nyfe has been compiled on OpenBSD, MacOS 13.x and Ubuntu 22.04.

The only real dependency is a decent libc and compiler.

```
$ make
# make install
```

# Tests

Nyfe includes the NIST SHA3 tests for SHA3-256, SHA3-512,
SHAKE128 and SHAKE256.

You can run them on your machine by invoking the right target.

```
$ make clean
$ make keccak-tests
```

The inclusion of these tests are to verify that the underlying
Keccak-f[1600,24] implementation is working correctly.

Usage
-----

First, you'll want to initialize nyfe and generate the default keyfile:

```
$ nyfe init
```

You can generate another keyfiles as needed:

```
$ nyfe keygen $HOME/.nyfe/different.key
```

You can also clone keyfiles, as a means of exporting them with
a different passphrase:


```
$ nyfe keyclone $HOME/.nyfe/different.key shared.key
```

Now you can encrypt some things with the default key:

```
$ nyfe encrypt myarchive.tar myarchive.nyfe
```

You can pipe straight into nyfe too if thats your thing:

```
$ tar zcv myarchive | nyfe encrypt -f $HOME/.nyfe/different.key myarchive.nyfe
```

You can also let nyfe output the encrypted data to stdout:

```
$ tar zcv myarchive | nyfe encrypt > myarchive.nyfe
```

Decrypting is pretty similar:

```
$ nyfe decrypt myarchive.nyfe myarchive.tar
```

You can also pipe into nyfe for decryption:

```
$ cat myarchive.nyfe | nyfe decrypt -f $HOME/.nyfe/different.key myarchive.tar
```

When decrypting Nyfe will refuse to output decrypted data to stdout since
that is a security risk as the data output is not yet verified and Nyfe does
not do chunks or intermediate tags.

# Defaults

When encrypting or decrypting, the -f flag specifies what keyfile to use.

If the -f flag is omitted, Nyfe will use $HOME/.nyfe/secret.key by default.

# Mascotte

Because mascottes are cool, here's SpongeNyfe:

<img src="logo.png" alt="Nyfe" width="256px" />
