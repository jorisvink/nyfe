# Nyfe

A software based file encryption tool where all cryptographic parts
are based on a single cryptographic function: Keccak-f[1600,24].

Nyfe is very minimal and lightweight as it has no external dependencies.

# License

Nyfe is licensed under the ISC license.

# Cryptography

WARNING: Nyfe uses cryptography that is currently not standarized.

**You** probably do not want to use this.

## Confidentiality and Integrity

Its confidentiality and integrity are protected using a permutation
based authenticated stream cipher: Agelas.

Agelas is an experimental AE construction aimed at trying to design
a simple to understand and easy to implement AE stream cipher based
on a Sponge function (in this case, Keccak-f[1600,24]).

Lots of inspiration was taken from Keyak and SpongeWrap.

## KDF

KMAC256 is used as a KDF for all derivations that take place.

KMAC256 is a NIST standard.

## Random

The random system in Nyfe is also based on the Keccak sponge.

In this case, it will instantiate an Agelas context with keys
that are derived from a random seed from the system which are
run through KMAC256.

It then allows random byte generation of up to 1024 bytes before
rekeying itself.

## Keys

The keys used with Agelas are derived from strong 256-bit symmetrical
secrets that are stored in keyfiles in combination with unique per-file seeds.

Separate keys and seeds are derived from the base symmetrical secret
for each new file.

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
that is a security risk as the data output is not yet verified.

# Defaults

When encrypting or decrypting, the -f flag specifies what keyfile to use.

If the -f flag is omitted, Nyfe will use $HOME/.nyfe/secret.key by default.

# Mascotte

Because mascottes are cool, here's SpongeNyfe:

<img src="logo.png" alt="Nyfe" width="256px" />
