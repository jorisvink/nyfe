Nyfe
----

A software based file encryption tool with some modern primitives
for confidentiality and integrity protection.

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
$ nyfe encrypt -f $HOME/.nyfe/nyfe.key myarchive.nyfe myarchive.tar
```
