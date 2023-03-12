Nyfe
----

A software based file encryption tool with some modern primitives
for confidentiality and integrity protection.

Nyfe is licensed under the ISC license.

Cryptography
------------

Nyfe provides confidentiality and integrity protection on its encrypted
data using XChaCha20 and KMAC256 respectively.

It does this with keys derived from strong 256-bit symmetrical secrets
that are stored in keyfiles.

Separate keys, nonce and seeds for confidentiality and integrity
protection are derived from the base symmetrical secret for each new file
that is encrypted, using KMAC256 as a PRF with separate customization labels
for each.

This project aims at producing a readable and trusted file encryption
tool for personal use.

It is also very minimal and lightweight as it has no external
dependencies (other than libbsd-dev on Linux).

The lack of meta-data in encrypted files is by design.

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

First, you'll want to generate a keyfile:

```
$ mkdir $HOME/.nyfe
$ nyfe keygen $HOME/.nyfe/nyfe.key
```

Now you can encrypt some things with that key:

```
$ nyfe encrypt -f $HOME/.nyfe/nyfe.key myarchive.tar myarchive.nyfe
```

You can pipe straight into nyfe too if thats your thing:

```
$ tar zcv myarchive | nyfe encrypt -f $HOME/.nyfe/nyfe.key - myarchive.nyfe
```

Decrypting is pretty similar:

```
$ nyfe decrypt -f $HOME/.nyfe/nyfe.key myarchive.nyfe myarchive.tar
```

You can also pipe into nyfe for decryption:

```
$ cat myarchive.nyfe | nyfe decrypt -f $HOME/.nyfe/nyfe.key - myarchive.tar
```

Defaults
--------

When encrypting or decrypting, the -f flag specifies what keyfile to use.

If the -f flag is omitted, Nyfe will use $HOME/.nyfe/secret.key by default.
