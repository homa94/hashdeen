# HASHDEEN version 1.0

Hashdeen is a simple script written in python3
It can encrypt and decrypt many type of hashes
Many times or once.

Such as: md5 md4 md5-sha1 sha1 sha224 sha256 
sha384 sha512 blake2b512 blake2s256 whirlpool 
ripemd160

### Examples:

#### For encryption:

`This will encrypt the word [password] for once:`

```
python3 hashdeen.py -t md5 -a password
```

`This will encrypt the word [password] for 10 times:`

```
python3 hashdeen.py -t md5 -a password -m 10
```

#### For decryption:

`This will decrypt the hash from wordlist once:`

```
python3 -t sha1 -e 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt
```

`This will decrypt the hash from wordlist 15 times:`

```
python3 -t sha1 -e 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -w wordlist.txt -m 15
```
