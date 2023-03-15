![](logo.jpg | width=256)

Nyfe
----

A software based file encryption tool with some modern primitives
for confidentiality and integrity protection.

Nyfe is licensed under the ISC license.

It is an excercise in building a file encryption tool based on
a single cryptographic function: Keccak.

You probably don't want to use this.

Cryptography
------------

WARNING: Nyfe uses experimental cryptography.

Its confidentiality and integrity are protected using a permutation
based authenticated stream cipher: Agelas.

Agelas is an experimental AE construction aimed at trying to design
a simple to understand and easy to implement AE stream cipher.

KMAC256 is used as a KDF for all derivations that take place.

The keys used with this cipher are derived from strong
256-bit symmetrical secrets that are stored in keyfiles.

Separate keys and seeds are derived from the base symmetrical secret
for each new file.

Nyfe is very minimal and lightweight as it has no external
dependencies (other than libbsd-dev on Linux).

The lack of meta-data in encrypted files is by design.

Performance
-----------

Performance is not considered at this stage, code correctness
and extreme care in handling sensitive data was.

Building
--------

Nyfe has been compiled on OpenBSD, MacOS 13.x and Ubuntu 22.04.

On Linux you will need libbsd-dev installed for readpassphrase().

Otherwise there are no dependencies other than a modern compiler.

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

Now you can encrypt some things with the default key:

```
$ nyfe encrypt myarchive.tar myarchive.nyfe
```

You can pipe straight into nyfe too if thats your thing:

```
$ tar zcv myarchive | nyfe encrypt -f $HOME/.nyfe/different.key - myarchive.nyfe
```

Decrypting is pretty similar:

```
$ nyfe decrypt myarchive.nyfe myarchive.tar
```

You can also pipe into nyfe for decryption:

```
$ cat myarchive.nyfe | nyfe decrypt -f $HOME/.nyfe/different.key - myarchive.tar
```

Defaults
--------

When encrypting or decrypting, the -f flag specifies what keyfile to use.

If the -f flag is omitted, Nyfe will use $HOME/.nyfe/secret.key by default.
